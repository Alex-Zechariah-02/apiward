// Offline clock-recovery command tests (recover-clock).

package integration

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func setHighWater(t *testing.T, dbPath string, when time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", store.DatabaseURI(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE deployment SET high_water = ? WHERE id = 1`, when.UnixMilli()); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverClockNoChangeWhenBehind(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})

	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "recover-clock")
	if code != 0 {
		t.Fatalf("recover-clock exited %d, want 0: %s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "no change") {
		t.Fatalf("output %q does not say no change", out)
	}
}

func TestRecoverClockResetsHighWater(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	ahead := time.Now().Add(24 * time.Hour)
	setHighWater(t, e.Database, ahead)

	e.Start(gatewaytest.Binaries.Plain)
	if state := e.Status().State; state != "clock_regression" {
		t.Fatalf("state %q before recovery, want clock_regression", state)
	}
	e.Stop()

	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "recover-clock")
	if code != 0 {
		t.Fatalf("recover-clock exited %d, want 0: %s", code, out)
	}

	e.Start(gatewaytest.Binaries.Plain)
	status, body := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice"))
	if status != http.StatusOK {
		t.Fatalf("GET /a/x after recovery: %d %s", status, body)
	}
}

func TestRecoverClockEndsTimedAuthority(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	role := "READER"
	e.MustOverride(admin, controller.OverrideRequest{
		Type: store.OverrideException, Control: store.ControlPermit, Operation: "write-a", Role: &role, ExpiresInSeconds: 600,
	}, gatewaytest.RevisionTag(1), "override-clock-reset-01")
	e.MustOverride(admin, controller.OverrideRequest{
		Type: store.OverrideContainment, Control: store.ControlOperation, Operation: "read-b", ExpiresInSeconds: 600,
	}, gatewaytest.RevisionTag(1), "override-clock-reset-02")
	cand := e.ProtectedPolicy()
	cand.Roles = append(cand.Roles, policy.Role{ID: "EXTRA"})
	_, activated := e.ProvisionalFrom(admin, cand, 1, 600, "provisional-clock-reset-01")
	e.Stop()

	ahead := time.Now().Add(24 * time.Hour)
	setHighWater(t, e.Database, ahead)

	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "recover-clock")
	if code != 0 {
		t.Fatalf("recover-clock exited %d, want 0: %s", code, out)
	}

	if prov := gatewaytest.QueryInt(t, e.Database, `SELECT coalesce(provisional, 0) FROM base WHERE id = 1`); prov != 0 {
		t.Fatalf("provisional = %d, want 0", prov)
	}
	if disp := gatewaytest.QueryString(t, e.Database, `SELECT coalesce(disposition, '') FROM activation WHERE revision = ?`, activated.Provisional); disp != store.DispositionTimedOut {
		t.Fatalf("activation disposition = %q, want %q", disp, store.DispositionTimedOut)
	}
	if active := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM override WHERE status = 'active'`); active != 0 {
		t.Fatalf("%d active overrides remain, want 0", active)
	}
	if expired := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM override WHERE status = 'expired'`); expired != 2 {
		t.Fatalf("%d expired overrides, want 2", expired)
	}

	var intents, resets int
	for _, ev := range auditRecords(e) {
		tr, _ := ev["transition"].(string)
		if !strings.HasPrefix(tr, "operator-clock-reset:") {
			continue
		}
		switch ev["kind"] {
		case "transition.intent":
			intents++
		case "operator.clock_reset":
			resets++
			if ev["old_high_water"] == nil || ev["new_high_water"] == nil {
				t.Fatalf("operator.clock_reset missing high_water fields: %+v", ev)
			}
			ended, _ := ev["ended_transitions"].([]any)
			if len(ended) < 3 {
				t.Fatalf("ended_transitions = %v, want at least 3 (provisional + 2 overrides)", ended)
			}
		}
	}
	if intents < 1 || resets != 1 {
		t.Fatalf("audit records: intents=%d resets=%d, want >=1 and 1", intents, resets)
	}

	e.Start(gatewaytest.Binaries.Plain)
	if status, _ := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice")); status != http.StatusOK {
		t.Fatalf("GET /a/x after recovery: %d, want 200", status)
	}
	if status, _ := e.Get("/b/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "bob")); status != http.StatusOK {
		t.Fatalf("GET /b/x after recovery (containment override ended): %d, want 200", status)
	}
}

func TestRecoverClockRefusedWhileRunning(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "recover-clock")
	if code == 0 {
		t.Fatalf("recover-clock succeeded while gateway was running: %s", out)
	}
	if !strings.Contains(strings.ToLower(out), "held") && !strings.Contains(strings.ToLower(out), "lock") {
		t.Fatalf("expected lock refusal message, got: %s", out)
	}
}
