// Activation authorisation and single provisional rules.

package integration

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Every lifecycle operation needs an authenticated administrator
// with manage_policy, the admin origin and the session's CSRF token; reads of
// the lifecycle need read or read_history. A client API token is not an
// administrator credential. Another administrator's idempotency key never
// returns someone else's receipt.
func TestLifecycleNeedsAuthorisedAdministrator(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	// Each enrolment restarts the gateway, so everyone logs in afterwards.
	_, readerPassword := addAdmin(e, gatewaytest.Binaries.Plain, "reader", "read")
	_, operatorPassword := addAdmin(e, gatewaytest.Binaries.Plain, "operator", "read,read_history,manage_policy")
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	reader := e.MustLogin("reader", readerPassword)
	operator := e.MustLogin("operator", operatorPassword)

	code, staged, body := e.Stage(harness, e.CpaCandidate(), `"r1"`, "stage-authorisation")
	if code != http.StatusCreated {
		t.Fatalf("staging: %d %s", code, body)
	}
	c := staged.Candidate.CandidateRecord
	activation := string(gatewaytest.MustJSON(map[string]any{"candidate": c.ID, "checksum": c.Checksum, "confirm_within_seconds": 60}))
	resolution := `{"revision":2}`
	apiToken := "Bearer " + gatewaytest.Issuer.TokenFor(t, "alice")
	before := e.Status()

	type attempt struct {
		name   string
		header []string
		status int
	}
	attempts := []attempt{
		{"no session", []string{"Origin", e.AdminOrigin()}, http.StatusUnauthorized},
		{"API client token", []string{"Origin", e.AdminOrigin(), "Authorization", apiToken}, http.StatusUnauthorized},
		{"read-only administrator", reader.Headers(e), http.StatusForbidden},
		{"no CSRF token", []string{"Cookie", gatewaytest.AdminCookie + "=" + harness.Cookie, "Origin", e.AdminOrigin()}, http.StatusForbidden},
		{"another origin", []string{"Cookie", gatewaytest.AdminCookie + "=" + harness.Cookie, gatewaytest.AdminCSRF, harness.CSRF, "Origin", "http://evil.example"}, http.StatusForbidden},
	}
	for _, path := range []string{"/admin/provisional", "/admin/provisional/confirm", "/admin/provisional/rollback"} {
		payload := activation
		if path != "/admin/provisional" {
			payload = resolution
		}
		for i, a := range attempts {
			header := append(slices.Clone(a.header), "If-Match", `"r1"`, "Idempotency-Key", fmt.Sprintf("authorisation-%02d-xxxx", i))
			if code, body, _ := e.AdminSend(http.MethodPost, path, payload, header...); code != a.status {
				t.Errorf("POST %s, %s: %d %s, want %d", path, a.name, code, body, a.status)
			}
		}
	}
	if code, _, _ := e.AdminSend(http.MethodGet, "/admin/provisional", ""); code != http.StatusUnauthorized {
		t.Errorf("anonymous provisional view: %d", code)
	}
	if code, _, _ := e.As(reader, http.MethodGet, "/admin/activations", ""); code != http.StatusForbidden {
		t.Errorf("activation history without read_history: %d", code)
	}
	if after := e.Status(); after.Generation != before.Generation || after.Provisional != 0 {
		t.Fatalf("refused calls changed the status: %+v", after)
	}

	// The operator activates; the harness administrator's same key and body
	// is its own new request, refused because a provisional base exists.
	if code, outcome, body := e.Activate(operator, c, 60, `"r1"`, "shared-key-0000001"); code != http.StatusOK || outcome.Provisional != 2 {
		t.Fatalf("operator activation: %d %s", code, body)
	}
	if code, outcome, body := e.Activate(harness, c, 60, `"r1"`, "shared-key-0000001"); code != http.StatusConflict || outcome.Reason != "PROVISIONAL_ACTIVE" ||
		outcome.Transition != "admin:"+gatewaytest.HarnessAdmin+":shared-key-0000001" {
		t.Fatalf("same key, other administrator: %d %s", code, body)
	}
	// A reader can see the provisional base but not resolve it.
	if code, _, _ := e.As(reader, http.MethodGet, "/admin/provisional", ""); code != http.StatusOK {
		t.Fatalf("reader provisional view: %d", code)
	}
	if code, _, _ := e.Resolve(reader, "rollback", 2, `"r1"`, "reader-rollback-xxxx"); code != http.StatusForbidden {
		t.Fatalf("reader rollback: %d", code)
	}
	if s := e.Status(); s.Provisional != 2 {
		t.Fatalf("status %+v", s)
	}
	expectEnforced(e, true, "")
	events := e.EventsWhen(func(events []map[string]any) bool {
		return gatewaytest.HasKinds(events, "admin.denied", "admin.rejected")
	})
	if gatewaytest.CountKind(events, "admin.denied") == 0 || gatewaytest.CountKind(events, "admin.rejected") == 0 {
		t.Fatal("refused administration calls were not recorded")
	}
	assertAbsent(t, e, apiToken[len("Bearer "):], harness.Cookie, reader.Cookie, harness.CSRF)
}

// Concurrent requests never produce a second provisional base or
// two dispositions: competing activations, repeated activations under one
// key, confirmation against rollback and confirmation against confirmation
// each have exactly one winner, and every loser is told what happened.
func TestOneProvisionalAndOneDisposition(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	// concurrently runs each call at the same moment from its own goroutine.
	concurrently := func(calls ...func()) {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, call := range calls {
			wg.Go(func() {
				<-start
				call()
			})
		}
		close(start)
		wg.Wait()
	}

	// Two candidates race for activation.
	_, first, _ := e.Stage(harness, e.CpaCandidate(), `"r1"`, "stage-race-first")
	_, second, _ := e.Stage(harness, e.ProtectedPolicy(), `"r1"`, "stage-race-second")
	var codes [2]int
	var outcomes [2]controller.Outcome
	concurrently(
		func() {
			codes[0], outcomes[0], _ = e.Activate(harness, first.Candidate.CandidateRecord, 60, `"r1"`, "race-activation-one")
		},
		func() {
			codes[1], outcomes[1], _ = e.Activate(harness, second.Candidate.CandidateRecord, 60, `"r1"`, "race-activation-two")
		},
	)
	slices.Sort(codes[:])
	if codes != [2]int{http.StatusOK, http.StatusConflict} {
		t.Fatalf("competing activations answered %v %+v", codes, outcomes)
	}
	winner := outcomes[0]
	if winner.Outcome != "committed" {
		winner = outcomes[1]
	}
	if loser := outcomes[0].Reason + outcomes[1].Reason; loser != "PROVISIONAL_ACTIVE" {
		t.Fatalf("losing activation reason %q", loser)
	}
	if s := e.Status(); s.Provisional != winner.Provisional || s.Generation != winner.Generation {
		t.Fatalf("status %+v, winner %+v", s, winner)
	}
	if code, _, body := e.Resolve(harness, "rollback", winner.Provisional, `"r1"`, "race-cleanup-rollback-1"); code != http.StatusOK {
		t.Fatalf("rollback: %d %s", code, body)
	}

	// One key sent twice at once applies once; both get the same receipt.
	_, third, _ := e.Stage(harness, e.CpaCandidate(), `"r1"`, "stage-race-third")
	concurrently(
		func() {
			codes[0], outcomes[0], _ = e.Activate(harness, third.Candidate.CandidateRecord, 60, `"r1"`, "race-same-key-0001")
		},
		func() {
			codes[1], outcomes[1], _ = e.Activate(harness, third.Candidate.CandidateRecord, 60, `"r1"`, "race-same-key-0001")
		},
	)
	if codes != [2]int{http.StatusOK, http.StatusOK} || outcomes[0].Transition != outcomes[1].Transition ||
		outcomes[0].Provisional != outcomes[1].Provisional || !outcomes[0].Deadline.Equal(outcomes[1].Deadline) {
		t.Fatalf("same key twice: %v %+v", codes, outcomes)
	}
	if s := e.Status(); !s.Deadline.Equal(outcomes[0].Deadline) {
		t.Fatalf("deadline %v, receipt %v", s.Deadline, outcomes[0].Deadline)
	}
	if code, _, body := e.Activate(harness, first.Candidate.CandidateRecord, 60, `"r1"`, "race-same-key-0001"); code != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "TRANSITION_ID_REUSED") {
		t.Fatalf("same key, other candidate: %d %s", code, body)
	}
	if code, _, body := e.Resolve(harness, "rollback", outcomes[0].Provisional, `"r1"`, "race-cleanup-rollback-2"); code != http.StatusOK {
		t.Fatalf("rollback: %d %s", code, body)
	}

	// Confirmation against rollback, and confirmation against confirmation,
	// over several rounds. The confirmed base moves with each confirmation.
	confirmed, candidateConfirmed := int64(1), false
	for round := range 6 {
		next := e.CpaCandidate()
		if candidateConfirmed {
			next = e.ProtectedPolicy()
		}
		_, activated := e.ProvisionalFrom(harness, next, confirmed, 60, fmt.Sprintf("race-round-%02d", round))
		actions := [2]string{"confirm", "rollback"}
		if round%2 == 1 {
			actions = [2]string{"confirm", "confirm"}
		}
		ifMatch := gatewaytest.RevisionTag(confirmed)
		concurrently(
			func() {
				codes[0], outcomes[0], _ = e.Resolve(harness, actions[0], activated.Provisional, ifMatch, fmt.Sprintf("race-%02d-first-xxxx", round))
			},
			func() {
				codes[1], outcomes[1], _ = e.Resolve(harness, actions[1], activated.Provisional, ifMatch, fmt.Sprintf("race-%02d-second-xxx", round))
			},
		)
		won := 0
		if codes[1] == http.StatusOK {
			won = 1
		}
		lost := 1 - won
		if codes[won] != http.StatusOK || codes[lost] != http.StatusConflict || outcomes[lost].Reason != "ALREADY_RESOLVED" ||
			outcomes[lost].Disposition != outcomes[won].Disposition {
			t.Fatalf("round %d (%v): %v %+v", round, actions, codes, outcomes)
		}
		if outcomes[won].Disposition == store.DispositionConfirmed {
			confirmed, candidateConfirmed = activated.Provisional, !candidateConfirmed
		}
		if s := e.Status(); s.Confirmed != confirmed || s.Provisional != 0 || s.Generation != outcomes[won].Generation {
			t.Fatalf("round %d status %+v", round, s)
		}
		expectEnforced(e, candidateConfirmed, outcomes[won].Generation)
	}

	e.Stop()
	list := storedActivations(t, e.Database)
	if len(list) != 8 {
		t.Fatalf("%d activations stored, want 8", len(list))
	}
	for _, a := range list {
		if a.Disposition != store.DispositionConfirmed && a.Disposition != store.DispositionRolledBack {
			t.Fatalf("activation %+v has no single explicit disposition", a)
		}
		n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE kind IN ('cpa.confirm', 'cpa.rollback', 'cpa.timeout')
			AND outcome = 'committed' AND result_candidate = ?`, a.Candidate)
		if n != 1 {
			t.Fatalf("activation of candidate %d has %d committed dispositions", a.Candidate, n)
		}
	}
}
