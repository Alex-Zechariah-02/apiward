// Audit gate and secret safety.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestAuditGateAndSecretSafety(t *testing.T) {
	t.Run("records outcomes without secrets", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		// An informational response before the final one must not be
		// recorded as the outcome.
		e.A.Handle = func(w http.ResponseWriter, r *http.Request) bool {
			w.WriteHeader(http.StatusEarlyHints)
			return false
		}
		e.Start(gatewaytest.Binaries.Fault)
		g := e.Status().Generation
		bearer := "Bearer SECRET-TOKEN-1234567890"

		e.Get("/a/x?token=SECRET-QUERY-VALUE", "Authorization", bearer)
		e.Get("/d?token=SECRET-QUERY-VALUE", "Authorization", bearer)
		e.Raw("GET /a/x%0A{\"kind\":\"forged\"} HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n")
		e.AssertReceipts(1, 0, 0)

		// AuditEvents fails the test if any line is not exactly one JSON record.
		events := e.EventsWhen(func(events []map[string]any) bool {
			return gatewaytest.CountKind(events, "request.rejected") >= 2 && gatewaytest.HasKinds(events, "request.admitted", "request.forwarded")
		})
		raw, _ := os.ReadFile(e.AuditLog)
		for _, secret := range []string{"SECRET-TOKEN", "SECRET-QUERY-VALUE", "Bearer"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("audit log contains %q", secret)
			}
		}
		seen := map[string]bool{}
		for _, ev := range events {
			if ev["kind"] == "forged" {
				t.Fatal("a request created a forged audit record")
			}
			if ev["kind"] == "request.forwarded" && ev["status"] != float64(http.StatusOK) {
				t.Fatalf("forwarded event %v, want final status 200", ev)
			}
			if strings.HasPrefix(ev["kind"].(string), "request.") {
				key := ev["kind"].(string) + "/" + ev["stage"].(string)
				seen[key] = true
				if ev["stage"] != "CAPTURE" && ev["generation"] != g {
					t.Fatalf("event %v lacks generation %s", ev, g)
				}
			}
		}
		for _, key := range []string{"request.admitted/AUDIT", "request.forwarded/FORWARD", "request.rejected/ACCESS", "request.rejected/CANONICAL"} {
			if !seen[key] {
				t.Fatalf("missing event %s in %v", key, events)
			}
		}
	})

	// An audit log the gateway cannot open stops its startup: nothing listens,
	// so nothing is admitted without its durable record, and the database is
	// released.
	unopenable := []struct {
		name    string
		prepare func(e *gatewaytest.Env)
	}{
		{"audit file cannot be opened", func(e *gatewaytest.Env) { os.Mkdir(e.AuditLog, 0o700) }},
		{"audit file read-only", func(e *gatewaytest.Env) {
			os.WriteFile(e.AuditLog, nil, 0o600)
			os.Chmod(e.AuditLog, 0o400)
			e.T.Cleanup(func() { os.Chmod(e.AuditLog, 0o600) })
		}},
		{"audit path is a symbolic link", func(e *gatewaytest.Env) {
			target := filepath.Join(e.Dir, "elsewhere.log")
			os.WriteFile(target, nil, 0o600)
			if err := os.Symlink(target, e.AuditLog); err != nil {
				e.T.Fatalf("creating the symbolic link: %v", err)
			}
		}},
	}
	for _, f := range unopenable {
		t.Run(f.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			f.prepare(e)
			e.Run(gatewaytest.Binaries.Plain)
			if code := e.WaitExit(); code != gatewaytest.ExitFailed || !strings.Contains(e.Output.String(), "audit log") {
				t.Fatalf("exit %d, want %d naming the audit log\n%s", code, gatewaytest.ExitFailed, e.Output)
			}
			if gatewaytest.Dialable(e.DataAddr) || gatewaytest.Dialable(e.Admin) {
				t.Fatal("a listener is open after the refused start")
			}
			e.AssertReceipts(0, 0, 0)
			st, err := store.OpenStore(e.Database)
			if err != nil {
				t.Fatalf("the database is held: %v", err)
			}
			st.Close()
		})
	}

	// An audit log that fails while the gateway runs stops every protected
	// admission and every policy change.
	failures := []struct {
		name  string
		fault string
	}{
		{"audit sync fails", "GATEWAY_FAULT=audit-sync"},
		{"no space left", "GATEWAY_FAULT=audit-full"},
	}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Fault, f.fault)
			before := e.Status()
			for range 3 {
				if code, _ := e.Get("/a/x"); code != http.StatusServiceUnavailable {
					t.Fatalf("admission with failed audit log: %d", code)
				}
			}
			// The unauthenticated health check reports the stored mode only:
			// it answers 200 and normal while every protected admission
			// fails. The authenticated status below reports the failure.
			if health := e.Health(); health != store.ModeNormal {
				t.Fatalf("health %q with a failed audit log", health)
			}
			if code, _ := e.Get("/zzz"); code != http.StatusNotFound {
				t.Fatalf("rejection with failed audit log: %d", code)
			}
			e.AssertReceipts(0, 0, 0)
			// A policy change needs its durable audit intent first, so the
			// membership API refuses to publish anything.
			code, body, _ := e.HarnessCall(http.MethodPut, "/admin/blocked-accounts/someone", `{"reason":"test containment"}`,
				"If-Match", `"r1"`, "Idempotency-Key", "audit-failure-probe")
			if code != http.StatusServiceUnavailable || !strings.Contains(body, "gateway_unavailable") {
				t.Fatalf("publication with failed audit log: %d %s", code, body)
			}
			if s := e.Status(); !s.AuditFailed || s.Generation != before.Generation {
				t.Fatalf("status %+v", s)
			}
		})
	}
}
