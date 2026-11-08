// Confirmation deadlines on a running gateway: rollback without traffic and a
// deadline set while the wall clock was ahead.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// With no request at all, the controller rolls back an expired
// provisional base on its own. A timer that fires after a confirmation or an
// explicit rollback changes nothing.
func TestTimeoutWithoutTraffic(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	baseGeneration := e.Status().Generation

	// Only Admin API status reads happen while the deadline passes.
	_, expiring := e.ProvisionalFrom(harness, e.CpaCandidate(), 1, 2, "quiet-timeout-01")
	gatewaytest.WaitFor(t, expiring.Deadline.Add(5*time.Second), "the automatic rollback", func() bool { return e.Status().Provisional == 0 })
	s := e.Status()
	if s.Revision != 1 || s.Confirmed != 1 || s.Generation != baseGeneration || !s.NotAfter.IsZero() {
		t.Fatalf("status after the timeout: %+v", s)
	}
	expectEnforced(e, false, baseGeneration)
	code, _, body := e.Resolve(harness, "confirm", 2, `"r1"`, "confirm-after-timeout")
	if outcome := fromJSON[controller.Outcome](t, body); code != http.StatusConflict || outcome.Reason != "ALREADY_RESOLVED" || outcome.Disposition != store.DispositionTimedOut {
		t.Fatalf("confirmation after the timeout: %d %s", code, body)
	}

	// Confirmed before its deadline: the timer must not undo it.
	_, kept := e.ProvisionalFrom(harness, e.CpaCandidate(), 1, 2, "quiet-timeout-02")
	if code, _, body := e.Resolve(harness, "confirm", kept.Provisional, `"r1"`, "quiet-timeout-02-confirm"); code != http.StatusOK {
		t.Fatalf("confirmation: %d %s", code, body)
	}
	// Rolled back before its deadline: the timer must not act again.
	_, withdrawn := e.ProvisionalFrom(harness, e.ProtectedPolicy(), kept.Provisional, 2, "quiet-timeout-03")
	if code, _, body := e.Resolve(harness, "rollback", withdrawn.Provisional, gatewaytest.RevisionTag(kept.Provisional), "quiet-timeout-03-rollback"); code != http.StatusOK {
		t.Fatalf("rollback: %d %s", code, body)
	}
	time.Sleep(time.Until(withdrawn.Deadline.Add(1500 * time.Millisecond)))
	if s := e.Status(); s.Confirmed != kept.Provisional || s.Provisional != 0 || s.Revision != kept.Provisional {
		t.Fatalf("status after the stale deadlines: %+v", s)
	}
	expectEnforced(e, true, "")

	events := e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "cpa.timed_out") > 0 })
	if n := gatewaytest.CountKind(events, "cpa.timed_out"); n != 1 {
		t.Fatalf("%d timeout events, want 1", n)
	}
	ev := findTransition(events, "cpa.timed_out", "auto-rollback:2")
	if ev == nil || ev["actor"] != "controller" || ev["revision"] != float64(1) || ev["provisional"] != float64(2) {
		t.Fatalf("timeout event %v", ev)
	}
	e.Stop()
	list := storedActivations(t, e.Database)
	want := []string{store.DispositionTimedOut, store.DispositionConfirmed, store.DispositionRolledBack}
	if len(list) != len(want) {
		t.Fatalf("stored activations %+v", list)
	}
	for i, a := range list {
		if a.Disposition != want[i] {
			t.Fatalf("activation %d disposition %q, want %q", a.Revision, a.Disposition, want[i])
		}
	}
	timedOut := list[0]
	if timedOut.ResolvedBy != "controller" || timedOut.Resolution != "auto-rollback:2" || timedOut.ResolvedAt.Before(timedOut.Deadline) ||
		timedOut.ResolvedAt.Sub(timedOut.Deadline) > time.Second {
		t.Fatalf("timed-out activation %+v: resolved %v after its deadline", timedOut, timedOut.ResolvedAt.Sub(timedOut.Deadline))
	}
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE id LIKE 'auto-rollback:%'`); n != 1 {
		t.Fatalf("%d automatic rollbacks, want 1", n)
	}
}

// A provisional base activated while the wall clock is an hour ahead, with
// the clock then set back, still rolls back after its own two seconds rather
// than an hour later.
func TestDeadlineSetWhileClockAhead(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	offset := filepath.Join(t.TempDir(), "wall-offset")
	setOffset := func(d time.Duration) {
		if err := os.WriteFile(offset, []byte(strconv.FormatInt(d.Milliseconds(), 10)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setOffset(0)
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_WALL_OFFSET="+offset)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	baseGeneration := e.Status().Generation

	setOffset(time.Hour)
	_, ahead := e.ProvisionalFrom(harness, e.CpaCandidate(), 1, 2, "clock-ahead-cpa-01")
	setOffset(0)
	expectEnforced(e, true, ahead.Generation)
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "the rollback after the clock moved back", func() bool { return e.Status().Provisional == 0 })
	expectEnforced(e, false, baseGeneration)
}
