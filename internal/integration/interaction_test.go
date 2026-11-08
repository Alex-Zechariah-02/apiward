// Candidates and provisional policies against active overrides.

package integration

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// These tests cover temporary overrides together with confirmed policy
// activation, and their behaviour across crashes, restarts, clock changes,
// damaged state, audit failures and a declared historical restore, through
// real gateway processes.

// upstreamCandidate moves API a from upstream A to upstream C and changes
// nothing else, so it touches no target an override in these tests relies on.
func upstreamCandidate(e *gatewaytest.Env) policy.Policy {
	p := e.ProtectedPolicy()
	p.Upstreams = append(p.Upstreams, policy.Upstream{ID: "C", Dial: e.C.Addr})
	p.APIs[0].Upstream = "C"
	return p
}

// A candidate that would change or invalidate an active override is refused
// at activation, naming the override, even when it was staged before the
// override existed; once the override is gone the same candidate activates.
// A candidate that touches no override's targets becomes provisional and then
// confirmed with the overrides still applied.
func TestCandidateAgainstActiveOverrides(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	basePolicy := e.ProtectedPolicy()
	basePolicy.Operations[0].Rate = gatewaytest.Rate(4, 60) // read-a
	gatewaytest.Seed(t, e.Database, basePolicy, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	// Staged before any override exists: grants READER the write permanently.
	grantCandidate := e.CpaCandidate()
	grantCandidate.Operations[0].Rate = gatewaytest.Rate(4, 60)
	code, early, body := e.Stage(harness, grantCandidate, `"r1"`, "stage-before-override")
	if code != http.StatusCreated {
		t.Fatalf("staging: %d %s", code, body)
	}
	grant := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 600), `"r1"`, "candidate-grant-0001")
	raise := e.MustOverride(harness, rateOverride(store.OverrideException, "read-a", 8, 600), `"r1"`, "candidate-raise-0001")
	closeB := e.MustOverride(harness, gatewaytest.OperationContainment("read-b", 600), `"r1"`, "candidate-close-0001")
	before := e.Status()

	refused := map[string]struct {
		policy policy.Policy
		holder int64
	}{}
	refused["same permit as an override"] = struct {
		policy policy.Policy
		holder int64
	}{grantCandidate, grant.Override}
	newCount := e.ProtectedPolicy()
	newCount.Operations[0].Rate = gatewaytest.Rate(6, 60)
	refused["rate count of an overridden rule"] = struct {
		policy policy.Policy
		holder int64
	}{newCount, raise.Override}
	noReader := e.ProtectedPolicy()
	noReader.Operations[0].Rate = gatewaytest.Rate(4, 60)
	noReader.Roles = []policy.Role{{ID: "WRITER"}}
	noReader.Permits = slices.DeleteFunc(noReader.Permits, func(p policy.Permit) bool { return p.Role == "READER" })
	refused["role an override grants removed"] = struct {
		policy policy.Policy
		holder int64
	}{noReader, grant.Override}
	narrower := e.ProtectedPolicy()
	narrower.Operations[0].Rate = gatewaytest.Rate(4, 60)
	narrower.Operations = append(narrower.Operations, policy.Operation{ID: "special-a", API: "a", Method: "GET", Target: "/a/special", Access: "allow", Auth: "none"})
	refused["more specific route inside an overridden prefix"] = struct {
		policy policy.Policy
		holder int64
	}{narrower, raise.Override}
	reRouted := e.ProtectedPolicy()
	reRouted.Operations[0].Rate = gatewaytest.Rate(4, 60)
	reRouted.Operations[3].Target = "/bee/*"
	refused["contained operation moved"] = struct {
		policy policy.Policy
		holder int64
	}{reRouted, closeB.Override}

	i := 0
	for name, r := range refused {
		staged := early.Candidate.CandidateRecord
		if name != "same permit as an override" {
			code, s, body := e.Stage(harness, r.policy, `"r1"`, fmt.Sprintf("stage-conflict-%02d-xxxx", i))
			if code != http.StatusCreated {
				t.Fatalf("%s: staging %d %s", name, code, body)
			}
			staged = s.Candidate.CandidateRecord
		}
		code, outcome, body := e.Activate(harness, staged, 60, `"r1"`, fmt.Sprintf("activate-conflict-%02d-x", i))
		if code != http.StatusConflict || outcome.Reason != "OVERRIDE_CONFLICT" || outcome.Override != r.holder {
			t.Errorf("%s: %d %s, want OVERRIDE_CONFLICT with override %d", name, code, body, r.holder)
		}
		i++
	}
	if s := e.Status(); s.Generation != before.Generation || s.Provisional != 0 {
		t.Fatalf("refused activations changed the status: %+v", s)
	}
	if n := len(activeOverrides(e, harness).Overrides); n != 3 {
		t.Fatalf("%d active overrides after the refusals", n)
	}

	// The grant ends; the candidate staged before it now activates, because
	// activation checks the overrides active at that moment.
	if code, _, body := revokeOverride(e, harness, grant.Override, "candidate-grant-revoke"); code != http.StatusOK {
		t.Fatalf("revocation: %d %s", code, body)
	}
	code, activated, body := e.Activate(harness, early.Candidate.CandidateRecord, 60, `"r1"`, "activate-after-revoke")
	if code != http.StatusOK || !strings.HasPrefix(activated.Generation, fmt.Sprintf("r2+o%d.%d-", raise.Override, closeB.Override)) {
		t.Fatalf("activation after the revocation: %d %s", code, body)
	}
	// Enforcement is the candidate (bob writes /a, served by C) with the
	// remaining overrides (/b closed; reads of /a limited to 8, not 4).
	e.ResetReceivers()
	if probe(e, "bob", http.MethodPost, "/a/item") != http.StatusOK || probe(e, "bob", http.MethodGet, "/b/x") != http.StatusForbidden {
		t.Fatal("provisional enforcement")
	}
	if got := sendAs(e, "alice", http.MethodGet, "/a/x", "", 9); !statusesAre(got, append(times(8, 200), 429)...) {
		t.Fatalf("alice reads under the provisional base with the rate override: %v", got)
	}
	e.AssertReceipts(0, 0, 9)

	// Confirmation keeps the overrides and does not remove or expire any.
	code, confirmed, body := e.Resolve(harness, "confirm", activated.Provisional, `"r1"`, "confirm-with-overrides")
	if code != http.StatusOK || !strings.HasPrefix(confirmed.Generation, fmt.Sprintf("r2+o%d.%d-", raise.Override, closeB.Override)) {
		t.Fatalf("confirmation: %d %s", code, body)
	}
	view := activeOverrides(e, harness)
	if view.Confirmed != 2 || view.Provisional != 0 || len(view.Overrides) != 2 || view.Generation != confirmed.Generation {
		t.Fatalf("overrides after the confirmation %+v", view)
	}
	e.ResetReceivers()
	if probe(e, "bob", http.MethodPost, "/a/item") != http.StatusOK || probe(e, "bob", http.MethodGet, "/b/x") != http.StatusForbidden {
		t.Fatal("enforcement after the confirmation")
	}
	e.AssertReceipts(0, 0, 1)
	events := e.EventsWhen(func(events []map[string]any) bool {
		return gatewaytest.CountKind(events, "cpa.rejected") >= len(refused)
	})
	conflicts := 0
	for _, ev := range events {
		if ev["kind"] == "cpa.rejected" && ev["reason"] == "OVERRIDE_CONFLICT" && ev["override"] != nil {
			conflicts++
		}
	}
	if conflicts != len(refused) {
		t.Fatalf("%d conflict refusal events, want %d", conflicts, len(refused))
	}
}

// While a provisional base is pending, no override can be created, extended
// or broadened, but overrides can still be revoked and still expire, without
// confirming anything. Rollback and timeout restore the earlier confirmed
// base with the overrides still active at that moment, never an earlier
// effective policy, and an override that ended stays ended.
func TestProvisionalRestrictsOverrides(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	closeB := e.MustOverride(harness, gatewaytest.OperationContainment("read-b", 600), `"r1"`, "provisional-close-01")
	grant := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 4), `"r1"`, "provisional-grant-01")
	limitAlice := e.MustOverride(harness, permitOverride(store.OverrideContainment, "WRITER", "read-a", 600), `"r1"`, "provisional-limit-01")
	earlierGenerations := map[string]bool{e.Status().Generation: true}

	_, activated := e.ProvisionalFrom(harness, upstreamCandidate(e), 1, 60, "provisional-restrict")
	if !strings.HasPrefix(activated.Generation, fmt.Sprintf("r2+o%d.%d.%d-", closeB.Override, grant.Override, limitAlice.Override)) {
		t.Fatalf("provisional generation %s", activated.Generation)
	}
	e.ResetReceivers()
	if probe(e, "bob", http.MethodPost, "/a/item") != http.StatusOK || probe(e, "bob", http.MethodGet, "/b/x") != http.StatusForbidden ||
		probe(e, "alice", http.MethodGet, "/a/x") != http.StatusForbidden {
		t.Fatal("provisional enforcement with overrides")
	}
	e.AssertReceipts(0, 0, 1)

	// No creation, extension or broadening while provisional.
	for i, r := range []controller.OverrideRequest{
		gatewaytest.OperationContainment("write-a", 600),
		permitOverride(store.OverrideException, "READER", "write-a", 3600), // same target, longer: an extension
		rateOverride(store.OverrideException, "read-a", 100, 60),           // a broadening
		permitOverride(store.OverrideContainment, "READER", "read-a", 60),  // even a restriction
	} {
		code, outcome, body := e.CreateOverride(harness, r, `"r1"`, fmt.Sprintf("provisional-create-%02d", i))
		if code != http.StatusConflict || outcome.Reason != "PROVISIONAL_ACTIVE" {
			t.Errorf("creation %d while provisional: %d %s", i, code, body)
		}
	}
	if code, body, _ := e.As(harness, http.MethodPost, "/admin/overrides/validate", string(gatewaytest.MustJSON(gatewaytest.OperationContainment("write-a", 60))), "If-Match", `"r1"`); code != http.StatusConflict ||
		!strings.Contains(body, "PROVISIONAL_ACTIVE") {
		t.Errorf("validation while provisional: %d %s", code, body)
	}

	// The short grant expires while provisional: the base stays provisional.
	gatewaytest.WaitFor(t, grant.Expires.Add(5*time.Second), "the expiry while provisional", func() bool { return len(e.Status().Overrides) == 2 })
	s := e.Status()
	if s.Provisional != activated.Provisional || s.Confirmed != 1 {
		t.Fatalf("status after the expiry %+v", s)
	}
	earlierGenerations[s.Generation] = true
	if probe(e, "bob", http.MethodPost, "/a/item") != http.StatusForbidden {
		t.Fatal("expired grant still enforced while provisional")
	}
	// A revocation while provisional.
	code, revoked, body := revokeOverride(e, harness, closeB.Override, "provisional-revoke-01")
	if code != http.StatusOK || revoked.Revision != activated.Provisional || !strings.HasPrefix(revoked.Generation, fmt.Sprintf("r2+o%d-", limitAlice.Override)) {
		t.Fatalf("revocation while provisional: %d %s", code, body)
	}
	if s := e.Status(); s.Provisional != activated.Provisional {
		t.Fatalf("the revocation ended the provisional base: %+v", s)
	}
	e.ResetReceivers()
	if probe(e, "bob", http.MethodGet, "/b/x") != http.StatusOK {
		t.Fatal("revoked containment still enforced")
	}
	e.AssertReceipts(0, 1, 0)

	// Explicit rollback: the confirmed base with the one override left.
	code, rolledBack, body := e.Resolve(harness, "rollback", activated.Provisional, `"r1"`, "provisional-rollback-1")
	if code != http.StatusOK || rolledBack.Revision != 1 || !strings.HasPrefix(rolledBack.Generation, fmt.Sprintf("r1+o%d-", limitAlice.Override)) ||
		earlierGenerations[rolledBack.Generation] {
		t.Fatalf("rollback: %d %s (earlier generations %v)", code, body, earlierGenerations)
	}
	e.ResetReceivers()
	if probe(e, "bob", http.MethodPost, "/a/item") != http.StatusForbidden || probe(e, "bob", http.MethodGet, "/b/x") != http.StatusOK ||
		probe(e, "alice", http.MethodGet, "/a/x") != http.StatusForbidden || probe(e, "bob", http.MethodGet, "/a/x") != http.StatusOK {
		t.Fatal("enforcement after the rollback")
	}
	e.AssertReceipts(1, 1, 0)

	// Timeout with an override that expired first: it is not revived.
	shortGrant := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 1), `"r1"`, "provisional-grant-02")
	_, timed := e.ProvisionalFrom(harness, upstreamCandidate(e), 1, 3, "provisional-timeout")
	gatewaytest.WaitFor(t, timed.Deadline.Add(5*time.Second), "the timeout", func() bool { return e.Status().Provisional == 0 })
	s = e.Status()
	if s.Confirmed != 1 || !strings.HasPrefix(s.Generation, fmt.Sprintf("r1+o%d-", limitAlice.Override)) || !slices.Equal(s.Overrides, []int64{limitAlice.Override}) {
		t.Fatalf("status after the timeout %+v", s)
	}
	e.ResetReceivers()
	if probe(e, "bob", http.MethodPost, "/a/item") != http.StatusForbidden {
		t.Fatal("an expired grant was revived by the timeout")
	}
	e.AssertReceipts(0, 0, 0)

	e.Stop()
	for _, o := range storedOverrides(t, e.Database) {
		want := map[int64]string{closeB.Override: store.OverrideRevoked, grant.Override: store.OverrideExpired, limitAlice.Override: store.OverrideActive, shortGrant.Override: store.OverrideExpired}[o.ID]
		if o.Status != want {
			t.Fatalf("override %d status %s, want %s", o.ID, o.Status, want)
		}
	}
	list := storedActivations(t, e.Database)
	if len(list) != 2 || list[0].Disposition != store.DispositionRolledBack || list[1].Disposition != store.DispositionTimedOut {
		t.Fatalf("activations %+v", list)
	}
}
