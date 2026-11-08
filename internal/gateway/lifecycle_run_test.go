// An application-owned controller runs policy lifecycles.

package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// A controller owned by an application runs the policy lifecycles through its
// own timers and the protected Admin API: a provisional base times out and
// rolls back, another is confirmed, an override expires, every change is
// audited, and a restart ends every administrator session while keeping the
// confirmed authority.
func TestOwnedControllerRunsPolicyLifecycles(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	c, _ := own(e, controllerConfig(e))
	if err := c.Start(testAdmin(c)); err != nil {
		t.Fatal(err)
	}
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	_, timed := e.ProvisionalFrom(harness, e.CpaCandidate(), 1, 1, "owned-timeout")
	if s := e.Status(); s.Provisional != timed.Provisional {
		t.Fatalf("status %+v, want provisional %d", s, timed.Provisional)
	}
	gatewaytest.WaitFor(t, timed.Deadline.Add(5*time.Second), "the automatic rollback", func() bool { return e.Status().Provisional == 0 })
	if s := e.Status(); s.Confirmed != 1 || s.Revision != 1 {
		t.Fatalf("after the rollback %+v", s)
	}

	_, kept := e.ProvisionalFrom(harness, e.CpaCandidate(), 1, 60, "owned-confirm")
	if code, _, body := e.Resolve(harness, "confirm", kept.Provisional, `"r1"`, "owned-confirm-resolve"); code != http.StatusOK {
		t.Fatalf("confirmation: %d %s", code, body)
	}
	if s := e.Status(); s.Confirmed != kept.Provisional || !s.NotAfter.IsZero() {
		t.Fatalf("after the confirmation %+v", s)
	}

	created := e.MustOverride(harness, gatewaytest.OperationContainment("read-a", 1), gatewaytest.RevisionTag(kept.Provisional), "owned-override-create")
	gatewaytest.WaitFor(t, created.Expires.Add(5*time.Second), "the override expiry", func() bool { return len(e.Status().Overrides) == 0 })

	recorded := []string{"cpa.activated", "cpa.timed_out", "cpa.confirmed", "tpo.created", "tpo.expired"}
	events := e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.HasKinds(events, recorded...) })
	for _, kind := range recorded {
		if gatewaytest.CountKind(events, kind) == 0 {
			t.Errorf("no %s event", kind)
		}
	}

	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	again, _ := own(e, controllerConfig(e))
	if err := again.Start(testAdmin(again)); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := e.As(harness, http.MethodGet, "/admin/session", ""); code != http.StatusUnauthorized {
		t.Fatalf("session after restart: %d", code)
	}
	if s := e.Status(); s.Confirmed != kept.Provisional || len(s.Overrides) != 0 {
		t.Fatalf("after restart %+v", s)
	}
}
