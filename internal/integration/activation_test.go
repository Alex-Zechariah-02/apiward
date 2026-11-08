// Confirmed activation helpers and rollback to the confirmed base.

package integration

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// These tests drive the confirmed-activation lifecycle through the real
// Admin API of a running gateway. Every enforcement claim is checked at the
// receivers: a status code alone does not show what was forwarded.

func confirmPolicy(e *gatewaytest.Env, s gatewaytest.AdminSession, policy policy.Policy, parent int64, key string) controller.Outcome {
	e.T.Helper()
	_, activation := e.ProvisionalFrom(s, policy, parent, 60, key)
	code, outcome, body := e.Resolve(s, "confirm", activation.Provisional, gatewaytest.RevisionTag(parent), "confirm-"+key)
	if code != http.StatusOK {
		e.T.Fatalf("confirmation: %d %s", code, body)
	}
	return outcome
}

// storedActivations reads every activation record of a stopped gateway.
func storedActivations(t *testing.T, path string) []store.ActivationRecord {
	t.Helper()
	db, err := sql.Open("sqlite", store.DatabaseURI(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT ` + store.ActivationColumns + ` FROM activation ORDER BY revision`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var list []store.ActivationRecord
	for rows.Next() {
		record, err := store.ScanActivation(rows)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, record)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return list
}

// expectEnforced sends three probes and checks the policy actually enforced:
// bob reading /b, bob writing /a and alice reading /a. Under the confirmed
// base bob may read /b (B) but not write, and /a is served by A; under the
// candidate bob may write but not read /b, and /a is served by C. A refused
// probe must reach no receiver. A non-empty generation must label every
// forwarded request.
func expectEnforced(e *gatewaytest.Env, candidate bool, generation string) {
	e.T.Helper()
	e.ResetReceivers()
	bobToken := "Bearer " + gatewaytest.Issuer.TokenFor(e.T, "bob")
	readB, _ := e.Get("/b/x", "Authorization", bobToken)
	writeA, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":1}`, "Authorization", bobToken)
	readA, _ := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(e.T, "alice"))

	want := [3]int{http.StatusOK, http.StatusForbidden, http.StatusOK}
	if candidate {
		want = [3]int{http.StatusForbidden, http.StatusOK, http.StatusOK}
	}
	if got := [3]int{readB, writeA, readA}; got != want {
		e.T.Fatalf("probes (bob GET /b, bob POST /a/item, alice GET /a) = %v, want %v (candidate policy: %v)", got, want, candidate)
	}
	if candidate {
		e.AssertReceipts(0, 0, 2)
	} else {
		e.AssertReceipts(1, 1, 0)
	}
	for _, rc := range []*gatewaytest.Receiver{e.A, e.B, e.C} {
		for _, r := range rc.Receipts() {
			if generation != "" && r.Generation != generation {
				e.T.Fatalf("%s received a request of generation %s, want %s", rc.Name, r.Generation, generation)
			}
		}
	}
}

// An explicit rollback restores the earlier confirmed base in real
// enforcement: the permission the candidate added stops working, the one it
// removed works again and the moved API returns to its original upstream.
// Rate counters carry over, so neither activation nor rollback grants a
// fresh quota.
func TestRollbackRestoresConfirmedBase(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	base := e.ProtectedPolicy()
	base.Operations[0].Rate = gatewaytest.Rate(3, 60) // read-a: three per minute per subject
	gatewaytest.Seed(t, e.Database, base, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	baseGeneration := e.Status().Generation
	aliceToken := "Bearer " + gatewaytest.Issuer.TokenFor(t, "alice")

	// alice uses two of her three reads under the confirmed base.
	for range 2 {
		if code, _ := e.Get("/a/x", "Authorization", aliceToken); code != http.StatusOK {
			t.Fatalf("read under the confirmed base: %d", code)
		}
	}

	candidate := e.CpaCandidate()
	candidate.Operations[0].Rate = gatewaytest.Rate(5, 60) // the candidate allows five
	_, activated := e.ProvisionalFrom(harness, candidate, 1, 60, "rollback-path-01")
	// Under the provisional rule two of five are used: three more.
	for i := range 4 {
		code, _ := e.Get("/a/x", "Authorization", aliceToken)
		if want := http.StatusOK; i == 3 {
			want = http.StatusTooManyRequests
			if code != want {
				t.Fatalf("fourth provisional read: %d, want 429", code)
			}
		} else if code != want {
			t.Fatalf("provisional read %d: %d", i, code)
		}
	}
	if n := e.C.Count(); n != 3 {
		t.Fatalf("C received %d reads, want 3", n)
	}

	code, rolledBack, body := e.Resolve(harness, "rollback", 2, `"r1"`, "rollback-path-rollback")
	if code != http.StatusOK || rolledBack.Disposition != store.DispositionRolledBack || rolledBack.Revision != 1 ||
		rolledBack.Provisional != 2 || rolledBack.RollbackTarget != 1 || rolledBack.Generation == "" || rolledBack.Generation == activated.Generation {
		t.Fatalf("rollback: %d %s", code, body)
	}
	if s := e.Status(); s.Revision != 1 || s.Confirmed != 1 || s.Provisional != 0 || !s.NotAfter.IsZero() || s.Generation != rolledBack.Generation {
		t.Fatalf("status after rollback: %+v", s)
	}
	// The restored rule (three) applies to the five reads already counted: no
	// free quota after the rollback.
	e.ResetReceivers()
	if code, _ := e.Get("/a/x", "Authorization", aliceToken); code != http.StatusTooManyRequests {
		t.Fatalf("read after rollback: %d, want 429", code)
	}
	e.AssertReceipts(0, 0, 0)

	// bob's permissions and the destination of /a are the confirmed base's.
	e.ResetReceivers()
	bobToken := "Bearer " + gatewaytest.Issuer.TokenFor(t, "bob")
	if code, _ := e.Get("/b/x", "Authorization", bobToken); code != http.StatusOK {
		t.Fatalf("restored permission: %d", code)
	}
	if code, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{}`, "Authorization", bobToken); code != http.StatusForbidden {
		t.Fatalf("withdrawn permission: %d", code)
	}
	if code, _ := e.Get("/a/x", "Authorization", bobToken); code != http.StatusOK {
		t.Fatalf("bob read of /a: %d", code)
	}
	e.AssertReceipts(1, 1, 0)
	for _, r := range append(e.A.Receipts(), e.B.Receipts()...) {
		if r.Generation != rolledBack.Generation {
			t.Fatalf("request served by generation %s, want the restored %s", r.Generation, rolledBack.Generation)
		}
	}
	// A generation's identity is derived from its revision and content, so
	// the restored base is exactly the earlier confirmed one.
	if rolledBack.Generation != baseGeneration {
		t.Fatalf("restored generation %s, original confirmed generation %s", rolledBack.Generation, baseGeneration)
	}

	// Repeats: the same request replays, another is told the disposition, and
	// a confirmation of the rolled-back revision is refused.
	if code, again, body := e.Resolve(harness, "rollback", 2, `"r1"`, "rollback-path-rollback"); code != http.StatusOK ||
		again.Transition != rolledBack.Transition || again.Disposition != store.DispositionRolledBack {
		t.Fatalf("retried rollback: %d %s", code, body)
	}
	for _, action := range []string{"rollback", "confirm"} {
		code, outcome, body := e.Resolve(harness, action, 2, `"r1"`, "after-rollback-"+action+"-x")
		if code != http.StatusConflict || outcome.Reason != "ALREADY_RESOLVED" || outcome.Disposition != store.DispositionRolledBack {
			t.Errorf("%s after rollback: %d %s", action, code, body)
		}
	}
	// With no provisional base there is nothing to resolve.
	if code, outcome, body := e.Resolve(harness, "rollback", 1, `"r1"`, "no-provisional-rollback"); code != http.StatusConflict || outcome.Reason != "NO_PROVISIONAL" {
		t.Fatalf("rollback without a provisional base: %d %s", code, body)
	}

	events := e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "cpa.rolled_back") > 0 })
	if ev := findTransition(events, "cpa.rolled_back", rolledBack.Transition); ev == nil || ev["revision"] != float64(1) ||
		ev["provisional"] != float64(2) || ev["generation"] != rolledBack.Generation {
		t.Fatalf("rollback event %v", ev)
	}
	e.Stop()
	list := storedActivations(t, e.Database)
	if len(list) != 1 || list[0].Disposition != store.DispositionRolledBack || list[0].Resolution != rolledBack.Transition {
		t.Fatalf("stored activations %+v", list)
	}
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM base WHERE confirmed = 1 AND provisional IS NULL`); n != 1 {
		t.Fatal("base is not confirmed revision 1")
	}
}
