// Expired or unavailable authority admits nothing.

package integration

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func TestExpiredProvisionalNeverServes(t *testing.T) {
	t.Run("expired while stopped", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		provisional := e.Policy(e.A, true)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Provisional: &provisional, Deadline: time.Now().Add(-time.Second)})
		e.Start(gatewaytest.Binaries.Plain)
		if s := e.Status(); s.Revision != 1 {
			t.Fatalf("serving revision %d, want confirmed revision 1", s.Revision)
		}
		if code, _ := e.Get("/b/x"); code != http.StatusNotFound {
			t.Fatalf("expired grant: %d", code)
		}
		e.AssertReceipts(0, 0, 0)
		e.Stop()
		if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE id = 'auto-rollback:2' AND outcome = 'committed'`); n != 1 {
			t.Fatalf("%d automatic rollbacks recorded, want 1", n)
		}
	})

	// Without a timer, the first request after the deadline is refused and
	// makes the controller roll back; no request is ever served by the
	// expired grant.
	t.Run("deadline passes while running without timer", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		provisional := e.Policy(e.A, true)
		deadline := time.Now().Add(3 * time.Second)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Provisional: &provisional, Deadline: deadline})
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=no-deadline-timer")
		if code, _ := e.Get("/b/x"); code != http.StatusOK {
			t.Fatalf("before deadline: %d", code)
		}
		time.Sleep(time.Until(deadline) + 200*time.Millisecond)
		if code, _ := e.Get("/b/x"); code != http.StatusServiceUnavailable {
			t.Fatalf("after deadline: %d, want 503", code)
		}
		limit := time.Now().Add(5 * time.Second)
		for e.Status().Revision != 1 {
			if time.Now().After(limit) {
				t.Fatal("the refused request did not lead to the automatic rollback")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if code, _ := e.Get("/b/x"); code != http.StatusNotFound {
			t.Fatalf("after rollback: %d, want 404", code)
		}
		e.AssertReceipts(0, 1, 0)
	})

	t.Run("deadline passes while running", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		provisional := e.Policy(e.A, true)
		deadline := time.Now().Add(2 * time.Second)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Provisional: &provisional, Deadline: deadline})
		e.Start(gatewaytest.Binaries.Plain)
		if s := e.Status(); s.Revision != 2 {
			t.Fatalf("before deadline serving %d, want provisional 2", s.Revision)
		}
		time.Sleep(time.Until(deadline))
		limit := time.Now().Add(5 * time.Second)
		for e.Status().Revision != 1 {
			if time.Now().After(limit) {
				t.Fatal("automatic rollback did not happen")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if code, _ := e.Get("/b/x"); code != http.StatusNotFound {
			t.Fatalf("after rollback: %d", code)
		}
		e.AssertReceipts(0, 0, 0)
	})

	for _, point := range []string{"timeout-before-commit", "timeout-after-commit"} {
		t.Run("crash at "+point, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			provisional := e.Policy(e.A, true)
			gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Provisional: &provisional, Deadline: time.Now().Add(-time.Second)})
			e.Launch(gatewaytest.Binaries.Fault, []string{"run", "--config", e.Config}, "GATEWAY_FAULT="+point)
			if code := e.WaitExit(); code != crashExit {
				t.Fatalf("exit code %d, want %d\n%s", code, crashExit, e.Output)
			}
			e.Start(gatewaytest.Binaries.Plain)
			if s := e.Status(); s.Revision != 1 {
				t.Fatalf("serving revision %d, want 1", s.Revision)
			}
			if code, _ := e.Get("/b/x"); code != http.StatusNotFound {
				t.Fatalf("expired grant after recovery: %d", code)
			}
			e.Stop()
			if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE id = 'auto-rollback:2'`); n != 1 {
				t.Fatalf("%d rollback records, want exactly 1", n)
			}
		})
	}

	t.Run("clock behind recorded time", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{HighWater: time.Now().Add(time.Hour)})
		e.Start(gatewaytest.Binaries.Plain)
		if s := e.Status(); s.State != "clock_regression" {
			t.Fatalf("state %q, want clock_regression", s.State)
		}
		if code, _ := e.Get("/a/x"); code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", code)
		}
		e.AssertReceipts(0, 0, 0)
	})
}

func TestUnavailableAuthorityAdmitsNothing(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(e *gatewaytest.Env)
		state   string // expected substring of the recorded reason
	}{
		{"missing database", func(e *gatewaytest.Env) {}, "missing or empty"},
		{"empty file", func(e *gatewaytest.Env) { os.WriteFile(e.Database, nil, 0o600) }, "missing or empty"},
		{"corrupt file", func(e *gatewaytest.Env) {
			gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			corrupt(e.T, e.Database)
		}, "unavailable"},
		{"checksum mismatch", func(e *gatewaytest.Env) {
			gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			db := gatewaytest.Inspect(e.T, e.Database)
			if _, err := db.Exec(`UPDATE revision SET document = ? WHERE id = 1`, gatewaytest.MustJSON(e.Policy(e.B, true))); err != nil {
				e.T.Fatal(err)
			}
			db.Close()
		}, "checksum mismatch"},
		{"stored revision in the earlier format", func(e *gatewaytest.Env) {
			gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			earlier := []byte(`{"upstreams":[{"id":"A","dial":"` + e.A.Addr + `"}],` +
				`"operations":[{"id":"read-a","method":"GET","target":"/a/*","upstream":"A","access":"allow"}]}`)
			db := gatewaytest.Inspect(e.T, e.Database)
			if _, err := db.Exec(`UPDATE revision SET document = ?, checksum = ? WHERE id = 1`, earlier, store.DocumentChecksum(earlier)); err != nil {
				e.T.Fatal(err)
			}
			db.Close()
		}, "SCHEMA_VERSION_UNSUPPORTED"},
		// A stored routing-only document never enforced authentication, so it
		// must not be served by a gateway that is expected to.
		{"stored revision in schema version 1", func(e *gatewaytest.Env) {
			gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			earlier := []byte(`{"schema_version":1,"profile":"routing-only","upstreams":[{"id":"A","dial":"` + e.A.Addr + `"}],` +
				`"apis":[{"id":"a","upstream":"A"}],` +
				`"operations":[{"id":"read-a","api":"a","method":"GET","target":"/a/*","access":"allow","auth":"required"}]}`)
			db := gatewaytest.Inspect(e.T, e.Database)
			if _, err := db.Exec(`UPDATE revision SET document = ?, checksum = ? WHERE id = 1`, earlier, store.DocumentChecksum(earlier)); err != nil {
				e.T.Fatal(err)
			}
			db.Close()
		}, "SCHEMA_VERSION_UNSUPPORTED"},
		{"recovery required", func(e *gatewaytest.Env) {
			gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Mode: store.ModeRecovery})
		}, store.ModeRecovery},
		{"bootstrap locked", func(e *gatewaytest.Env) {
			gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Mode: store.ModeBootstrap})
		}, store.ModeBootstrap},
		{"rollback recorded but provisional still active", func(e *gatewaytest.Env) {
			provisional := e.Policy(e.A, true)
			gatewaytest.Seed(e.T, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{Provisional: &provisional, Deadline: time.Now().Add(-time.Second)})
			db := gatewaytest.Inspect(e.T, e.Database)
			if _, err := db.Exec(`INSERT INTO transition (id, kind, actor, target, digest, outcome, reason, result_revision, committed_at)
				VALUES ('auto-rollback:2', 'rollback', 'controller', 'revision 2', 'auto-rollback:2', 'committed', '', 1, 0)`); err != nil {
				e.T.Fatal(err)
			}
			db.Close()
		}, "auto-rollback:2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			tc.prepare(e)
			e.Start(gatewaytest.Binaries.Fault)
			wantHealth, wantMutation := "unavailable", http.StatusServiceUnavailable
			if tc.state == store.ModeRecovery || tc.state == store.ModeBootstrap {
				wantHealth, wantMutation = tc.state, http.StatusOK
			}
			if health := e.Health(); health != wantHealth {
				t.Fatalf("health %q, want %q", health, wantHealth)
			}
			if reason := e.UnavailableReason(); !strings.Contains(reason, tc.state) {
				t.Fatalf("recorded reason %q, want it to contain %q", reason, tc.state)
			}
			for _, path := range []string{"/a/x", "/b/x", "/d"} {
				if code, _ := e.Get(path); code != http.StatusServiceUnavailable {
					t.Fatalf("GET %s: %d, want 503", path, code)
				}
			}
			e.AssertReceipts(0, 0, 0)
			if _, code := e.Publish(controller.Change{ID: "x", Expected: 1, Policy: gatewaytest.MustJSON(e.Policy(e.A, true))}); code != http.StatusServiceUnavailable {
				t.Fatalf("publication accepted in unavailable state: %d", code)
			}
			code, body, _ := e.HarnessCall(http.MethodPut, "/admin/blocked-accounts/someone", `{"reason":"contain"}`,
				"If-Match", `"r1"`, "Idempotency-Key", "unavailable-probe-1")
			if code != wantMutation {
				t.Fatalf("independent containment in unavailable state: %d %s, want %d", code, body, wantMutation)
			}
			if e.Health() != wantHealth {
				t.Fatal("containment changed deployment mode")
			}
		})
	}

	t.Run("missing database is not created", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		e.Start(gatewaytest.Binaries.Plain)
		e.Stop()
		if _, err := os.Stat(e.Database); !os.IsNotExist(err) {
			t.Fatalf("database was created on startup: %v", err)
		}
	})

	t.Run("second instance on the same database", func(t *testing.T) {
		first := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, first.Database, first.Policy(first.A, false), gatewaytest.SeedOptions{})
		first.Start(gatewaytest.Binaries.Plain)

		second := gatewaytest.NewEnv(t)
		second.Database = first.Database
		second.WriteConfig(gatewaytest.ConfigOptions{})
		second.Launch(gatewaytest.Binaries.Plain, []string{"run", "--config", second.Config})
		if code := second.WaitExit(); code == 0 {
			t.Fatalf("second instance kept running\n%s", second.Output)
		}
		if !strings.Contains(second.Output.String(), "held by another gateway process") {
			t.Fatalf("second instance failed for another reason:\n%s", second.Output)
		}
		if code, _ := first.Get("/a/x"); code != http.StatusOK {
			t.Fatalf("first instance after second start attempt: %d", code)
		}
	})
}
