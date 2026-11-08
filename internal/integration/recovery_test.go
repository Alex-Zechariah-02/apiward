// Crash recovery during publication, lifecycle and timeout.

package integration

import (
	"net/http"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

const crashExit = 86

func TestCrashDuringPublication(t *testing.T) {
	cases := []struct {
		point     string
		committed bool   // whether the transition survives the crash
		receipt   string // publication receipt recorded after restart
	}{
		{"before-commit", false, ""},
		{"after-commit", true, "reconciliation"},
		{"after-swap", true, "reconciliation"},
		{"after-receipt", true, "publisher"},
	}
	for _, tc := range cases {
		t.Run(tc.point, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT="+tc.point)

			change := controller.Change{ID: "add-b", Expected: 1, Policy: gatewaytest.MustJSON(e.Policy(e.A, true))}
			if _, code := e.Publish(change); code != 0 {
				t.Fatalf("publication answered %d instead of crashing", code)
			}
			if code := e.WaitExit(); code != crashExit {
				t.Fatalf("exit code %d, want %d\n%s", code, crashExit, e.Output)
			}

			wantRevisions, wantCommitted := 1, 0
			if tc.committed {
				wantRevisions, wantCommitted = 2, 1
			}
			if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM revision`); n != wantRevisions {
				t.Fatalf("after crash: %d revisions, want %d", n, wantRevisions)
			}
			if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE outcome = 'committed'`); n != wantCommitted {
				t.Fatalf("after crash: %d committed transitions, want %d", n, wantCommitted)
			}

			e.Start(gatewaytest.Binaries.Fault)
			s := e.Status()
			if s.Revision != int64(wantRevisions) {
				t.Fatalf("restart serves revision %d, want %d", s.Revision, wantRevisions)
			}
			want := http.StatusNotFound
			if tc.committed {
				want = http.StatusOK
			}
			if code, _ := e.Get("/b/x"); code != want {
				t.Fatalf("GET /b/x after restart: %d, want %d", code, want)
			}

			outcome, code := e.Publish(change)
			if code != http.StatusOK || outcome.Revision != 2 {
				t.Fatalf("retry with the same identity: %d %+v", code, outcome)
			}
			e.Stop()
			if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM revision`); n != 2 {
				t.Fatalf("after retry: %d revisions, want 2 (applied exactly once)", n)
			}
			if tc.committed {
				var by string
				db := gatewaytest.Inspect(t, e.Database)
				db.QueryRow(`SELECT published_by FROM transition WHERE id = 'add-b'`).Scan(&by)
				db.Close()
				if by != tc.receipt {
					t.Fatalf("published_by %q, want %q", by, tc.receipt)
				}
			}
		})
	}
}

// A crash at each point of an activation, confirmation or
// rollback. Before its commit nothing changed and the retried request applies
// once; from the commit on, the restarted gateway serves the committed state,
// completes the receipts, records the outcome event exactly once, and the
// retried request returns the recorded receipt.
func TestLifecycleSurvivesCrash(t *testing.T) {
	cases := []struct {
		action    string // activate, confirm or rollback
		point     string
		committed bool
	}{
		{"activate", "before-commit", false},
		{"activate", "commit-partway", false},
		{"activate", "after-commit", true},
		{"activate", "after-swap", true},
		{"activate", "after-receipt", true},
		{"activate", "after-outcome", true},
		{"confirm", "confirm-before-commit", false},
		{"confirm", "confirm-after-commit", true},
		{"confirm", "confirm-after-swap", true},
		{"confirm", "confirm-after-receipt", true},
		{"confirm", "after-outcome", true},
		{"rollback", "rollback-before-commit", false},
		{"rollback", "rollback-after-commit", true},
		{"rollback", "rollback-after-swap", true},
		{"rollback", "rollback-after-receipt", true},
		{"rollback", "after-outcome", true},
	}
	for _, tc := range cases {
		t.Run(tc.action+" "+tc.point, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Plain)
			harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			code, staged, body := e.Stage(harness, e.CpaCandidate(), `"r1"`, "stage-crash-candidate")
			if code != http.StatusCreated {
				t.Fatalf("staging: %d %s", code, body)
			}
			candidate := staged.Candidate.CandidateRecord
			if tc.action != "activate" {
				if code, _, body := e.Activate(harness, candidate, 60, `"r1"`, "activate-before-crash"); code != http.StatusOK {
					t.Fatalf("activation: %d %s", code, body)
				}
			}
			const key = "crash-case-request"
			send := func() (int, controller.Outcome, string) {
				if tc.action == "activate" {
					return e.Activate(harness, candidate, 60, `"r1"`, key)
				}
				return e.Resolve(harness, tc.action, 2, `"r1"`, key)
			}

			e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT="+tc.point)
			harness = e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			if code, _, body := send(); code != 0 {
				t.Fatalf("answered %d instead of crashing: %s", code, body)
			}
			if code := e.WaitExit(); code != crashExit {
				t.Fatalf("exit code %d, want %d\n%s", code, crashExit, e.Output)
			}

			// What a restart serves: the committed state, or the earlier one.
			type state struct{ confirmed, provisional int64 }
			before := map[string]state{"activate": {1, 0}, "confirm": {1, 2}, "rollback": {1, 2}}[tc.action]
			after := map[string]state{"activate": {1, 2}, "confirm": {2, 0}, "rollback": {1, 0}}[tc.action]
			want := before
			if tc.committed {
				want = after
			}
			e.Start(gatewaytest.Binaries.Plain)
			harness = e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			s := e.Status()
			if s.Confirmed != want.confirmed || s.Provisional != want.provisional {
				t.Fatalf("after restart: %+v, want confirmed %d provisional %d", s, want.confirmed, want.provisional)
			}
			expectEnforced(e, want.provisional != 0 || want.confirmed == 2, s.Generation)

			// The retry applies once, or returns what was recorded.
			code, outcome, body := send()
			if code != http.StatusOK || outcome.Outcome != "committed" || outcome.Transition != "admin:"+gatewaytest.HarnessAdmin+":"+key {
				t.Fatalf("retry: %d %s", code, body)
			}
			s = e.Status()
			if s.Confirmed != after.confirmed || s.Provisional != after.provisional {
				t.Fatalf("after retry: %+v", s)
			}
			if tc.action == "activate" && !outcome.Deadline.Equal(s.Deadline) {
				t.Fatalf("retry deadline %v, stored %v", outcome.Deadline, s.Deadline)
			}
			if tc.action != "activate" && outcome.Disposition == "" {
				t.Fatalf("retry receipt without its disposition: %s", body)
			}

			e.Stop()
			id := "admin:" + gatewaytest.HarnessAdmin + ":" + key
			if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE id = ? AND outcome = 'committed'
				AND published_at IS NOT NULL AND audited_at IS NOT NULL`, id); n != 1 {
				t.Fatalf("%d complete records of %s", n, id)
			}
			receipt := "publisher"
			if tc.point == "after-commit" || tc.point == "after-swap" || tc.point == "confirm-after-commit" ||
				tc.point == "confirm-after-swap" || tc.point == "rollback-after-commit" || tc.point == "rollback-after-swap" {
				receipt = "reconciliation"
			}
			if by := gatewaytest.QueryString(t, e.Database, `SELECT published_by FROM transition WHERE id = ?`, id); by != receipt {
				t.Fatalf("publication receipt by %q, want %q", by, receipt)
			}
			kind := map[string]string{"activate": "cpa.activated", "confirm": "cpa.confirmed", "rollback": "cpa.rolled_back"}[tc.action]
			outcomes := 0
			for _, ev := range e.AuditEvents() {
				if ev["kind"] == kind && ev["transition"] == id {
					outcomes++
				}
			}
			if outcomes != 1 {
				t.Fatalf("%d %s events for %s, want 1", outcomes, kind, id)
			}
			list := storedActivations(t, e.Database)
			wantDisposition := map[string]string{"activate": "", "confirm": store.DispositionConfirmed, "rollback": store.DispositionRolledBack}[tc.action]
			if len(list) != 1 || list[0].Disposition != wantDisposition {
				t.Fatalf("stored activations %+v", list)
			}
		})
	}
}

// A crash while the running gateway times out a provisional base is
// recovered at the next start, before anything is served, with one timeout.
func TestTimeoutSurvivesCrash(t *testing.T) {
	for _, point := range []string{"timeout-before-commit", "timeout-after-commit", "timeout-after-swap", "timeout-after-receipt"} {
		t.Run(point, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT="+point)
			harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			e.ProvisionalFrom(harness, e.CpaCandidate(), 1, 2, "timeout-crash-case")
			if code := e.WaitExit(); code != crashExit {
				t.Fatalf("exit code %d, want %d\n%s", code, crashExit, e.Output)
			}
			e.Start(gatewaytest.Binaries.Plain)
			if s := e.Status(); s.Revision != 1 || s.Provisional != 0 || s.Confirmed != 1 {
				t.Fatalf("after restart: %+v", s)
			}
			expectEnforced(e, false, "")
			e.Stop()
			if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE id = 'auto-rollback:2' AND outcome = 'committed'
				AND published_at IS NOT NULL AND audited_at IS NOT NULL`); n != 1 {
				t.Fatalf("%d complete timeout records", n)
			}
			if list := storedActivations(t, e.Database); len(list) != 1 || list[0].Disposition != store.DispositionTimedOut {
				t.Fatalf("stored activations %+v", list)
			}
			if n := gatewaytest.CountKind(e.AuditEvents(), "cpa.timed_out"); n != 1 {
				t.Fatalf("%d timeout events, want 1", n)
			}
		})
	}
}
