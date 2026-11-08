// Overrides with concurrent activation, rate rules and load.

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// An activation and an override creation sent at the same moment are
// decided in one order: if the activation is first, the creation is refused
// as provisional; if the creation is first, the conflicting candidate is
// refused. Confirmation, rollback and an override's expiry racing at a
// provisional deadline give each its single final disposition.
func TestConcurrentOverridesAndActivation(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

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

	orders := map[string]int{}
	for round := range 8 {
		_, staged, _ := e.Stage(harness, e.CpaCandidate(), `"r1"`, fmt.Sprintf("race-stage-%02d-xxxx", round))
		var activation, creation controller.Outcome
		var activationCode, creationCode int
		concurrently(
			func() {
				activationCode, activation, _ = e.Activate(harness, staged.Candidate.CandidateRecord, 60, `"r1"`, fmt.Sprintf("race-activate-%02d-xx", round))
			},
			func() {
				creationCode, creation, _ = e.CreateOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 600), `"r1"`, fmt.Sprintf("race-create-%02d-xxxx", round))
			},
		)
		switch {
		case activationCode == http.StatusOK && creationCode == http.StatusConflict && creation.Reason == "PROVISIONAL_ACTIVE":
			orders["activation first"]++
			if code, _, body := e.Resolve(harness, "rollback", activation.Provisional, `"r1"`, fmt.Sprintf("race-rollback-%02d-x", round)); code != http.StatusOK {
				t.Fatalf("rollback: %d %s", code, body)
			}
		case creationCode == http.StatusCreated && activationCode == http.StatusConflict && activation.Reason == "OVERRIDE_CONFLICT":
			orders["creation first"]++
			if code, _, body := revokeOverride(e, harness, creation.Override, fmt.Sprintf("race-revoke-%02d-xxx", round)); code != http.StatusOK {
				t.Fatalf("revocation: %d %s", code, body)
			}
		default:
			t.Fatalf("round %d: activation %d %+v, creation %d %+v", round, activationCode, activation, creationCode, creation)
		}
		if s := e.Status(); s.Provisional != 0 || len(s.Overrides) != 0 || s.Confirmed != 1 {
			t.Fatalf("round %d left %+v", round, s)
		}
	}
	t.Logf("serial orders observed: %v", orders)

	// Confirmation, rollback and an override expiry at a 2 s deadline.
	confirmed := int64(1)
	for round := range 4 {
		o := e.MustOverride(harness, gatewaytest.OperationContainment("read-b", 2), gatewaytest.RevisionTag(confirmed), fmt.Sprintf("race-expiring-%02d-x", round))
		_, activated := e.ProvisionalFrom(harness, upstreamCandidate(e), confirmed, 2, fmt.Sprintf("race-deadline-%02d", round))
		if round%2 == 1 {
			// The other candidate: back to the protected policy.
			e.Resolve(harness, "rollback", activated.Provisional, gatewaytest.RevisionTag(confirmed), fmt.Sprintf("race-reset-%02d-xxxxx", round))
			_, activated = e.ProvisionalFrom(harness, e.ProtectedPolicy(), confirmed, 2, fmt.Sprintf("race-deadline-b-%02d", round))
		}
		time.Sleep(time.Until(o.Expires.Add(-15 * time.Millisecond)))
		var codes [3]int
		var outcomes [3]controller.Outcome
		concurrently(
			func() {
				codes[0], outcomes[0], _ = e.Resolve(harness, "confirm", activated.Provisional, gatewaytest.RevisionTag(confirmed), fmt.Sprintf("race-confirm-%02d-xxx", round))
			},
			func() {
				codes[1], outcomes[1], _ = e.Resolve(harness, "rollback", activated.Provisional, gatewaytest.RevisionTag(confirmed), fmt.Sprintf("race-rollback-%02d-xx", round))
			},
			func() {
				codes[2], outcomes[2], _ = revokeOverride(e, harness, o.Override, fmt.Sprintf("race-revoke-%02d-xxxx", round))
			},
		)
		gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "the provisional base and override to end", func() bool {
			s := e.Status()
			return s.Provisional == 0 && len(s.Overrides) == 0
		})
		s := e.Status()
		if s.Confirmed == activated.Provisional {
			confirmed = activated.Provisional
		}
		t.Logf("round %d: confirm %d %s, rollback %d %s, revoke %d %s", round, codes[0], outcomes[0].Reason+outcomes[0].Disposition,
			codes[1], outcomes[1].Reason+outcomes[1].Disposition, codes[2], outcomes[2].Reason+outcomes[2].Disposition)
	}

	e.Stop()
	for _, a := range storedActivations(t, e.Database) {
		n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE kind IN ('cpa.confirm', 'cpa.rollback', 'cpa.timeout')
			AND outcome = 'committed' AND result_candidate = ?`, a.Candidate)
		if a.Disposition == "" || n != 1 {
			t.Fatalf("activation %+v has %d committed dispositions", a, n)
		}
	}
	for _, o := range storedOverrides(t, e.Database) {
		if o.Status == store.OverrideActive {
			t.Fatalf("override %+v still active", o)
		}
		if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE outcome = 'committed' AND kind IN ('tpo.revoke', 'tpo.expire') AND id = ?`, o.Resolution); n != 1 {
			t.Fatalf("override %d has %d ending transitions", o.ID, n)
		}
	}
}

// A rate override applies to the provisional base too and keeps the
// counters across activation and rollback; an override that expired while
// the base was provisional is not restored by the rollback. Decisions are
// worked out by hand from the admission rule at a controlled limiter time.
func TestRateOverrideAcrossActivation(t *testing.T) {
	ratePolicy := func(e *gatewaytest.Env) policy.Policy {
		p := e.ProtectedPolicy()
		p.Operations[0].Rate = gatewaytest.Rate(3, 60) // read-a: 3 per minute per subject
		return p
	}
	e, clock := newRateEnv(t, ratePolicy, base)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	candidate := upstreamCandidate(e)
	candidate.Operations[0].Rate = gatewaytest.Rate(3, 60)

	if got := sendAs(e, "alice", http.MethodGet, "/a/x", "", 2); !statusesAre(got, 200, 200) {
		t.Fatalf("alice under the base: %v", got)
	}
	raise := e.MustOverride(harness, rateOverride(store.OverrideException, "read-a", 5, 600), `"r1"`, "rate-cpa-raise-0001")
	_, activated := e.ProvisionalFrom(harness, candidate, 1, 60, "rate-cpa-activate")
	// C=2 under the provisional base with the exception to 5: three more.
	if got := sendAs(e, "alice", http.MethodGet, "/a/x", "", 4); !statusesAre(got, 200, 200, 200, 429) {
		t.Fatalf("alice while provisional: %v", got)
	}
	if code, rolledBack, body := e.Resolve(harness, "rollback", activated.Provisional, `"r1"`, "rate-cpa-rollback-1"); code != http.StatusOK ||
		!strings.HasPrefix(rolledBack.Generation, fmt.Sprintf("r1+o%d-", raise.Override)) {
		t.Fatalf("rollback: %d %s", code, body)
	}
	// Same counter, same count 5: still refused, nothing granted back.
	if got := sendAs(e, "alice", http.MethodGet, "/a/x", "", 1); !statusesAre(got, 429) {
		t.Fatalf("alice after the rollback: %v", got)
	}
	if code, _, body := revokeOverride(e, harness, raise.Override, "rate-cpa-revoke-01"); code != http.StatusOK {
		t.Fatalf("revocation: %d %s", code, body)
	}

	// A fresh window; an exception that expires while provisional.
	clock.set(base + 180_000)
	short := e.MustOverride(harness, rateOverride(store.OverrideException, "read-a", 5, 2), `"r1"`, "rate-cpa-short-0001")
	_, activated = e.ProvisionalFrom(harness, candidate, 1, 60, "rate-cpa-activate-2")
	if got := sendAs(e, "alice", http.MethodGet, "/a/x", "", 4); !statusesAre(got, times(4, 200)...) {
		t.Fatalf("alice under the short exception: %v", got)
	}
	gatewaytest.WaitFor(t, short.Expires.Add(5*time.Second), "the expiry", func() bool { return len(e.Status().Overrides) == 0 })
	// Base count 3 against C=4.
	if got := sendAs(e, "alice", http.MethodGet, "/a/x", "", 1); !statusesAre(got, 429) {
		t.Fatalf("alice after the expiry: %v", got)
	}
	if code, rolledBack, body := e.Resolve(harness, "rollback", activated.Provisional, `"r1"`, "rate-cpa-rollback-2"); code != http.StatusOK ||
		!strings.HasPrefix(rolledBack.Generation, "r1-") {
		t.Fatalf("rollback: %d %s", code, body)
	}
	if got := sendAs(e, "alice", http.MethodGet, "/a/x", "", 1); !statusesAre(got, 429) {
		t.Fatalf("alice after the second rollback: %v", got)
	}
	// bob, never counted, has the base's 3.
	if got := sendAs(e, "bob", http.MethodGet, "/a/x", "", 4); !statusesAre(got, 200, 200, 200, 429) {
		t.Fatalf("bob: %v", got)
	}
}

// Under continuous traffic, overrides are created and revoked repeatedly:
// every request is decided and forwarded by one generation, and a write only
// the grant permits reaches the upstream only under a generation that has
// the grant.
func TestOverridesUnderLoad(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	withGrant := map[string]bool{}
	withoutGrant := map[string]bool{e.Status().Generation: true}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var unexpected sync.Map
	var forwarded atomic.Int64
	bobToken := "Bearer " + gatewaytest.Issuer.TokenFor(t, "bob")
	aliceToken := "Bearer " + gatewaytest.Issuer.TokenFor(t, "alice")
	for i := range 6 {
		write := i%2 == 0
		wg.Go(func() {
			client := &http.Client{Timeout: 10 * time.Second}
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest(http.MethodGet, "http://"+e.DataAddr+"/a/x", nil)
				req.Header.Set("Authorization", aliceToken)
				if write {
					req, _ = http.NewRequest(http.MethodPost, "http://"+e.DataAddr+"/a/item", strings.NewReader(`{"n":1}`))
					req.Header.Set("Authorization", bobToken)
					req.Header.Set("Content-Type", "application/json")
				}
				resp, err := client.Do(req)
				if err != nil {
					unexpected.Store(err.Error(), true)
					continue
				}
				resp.Body.Close()
				switch {
				case resp.StatusCode == http.StatusOK:
					forwarded.Add(1)
				case resp.StatusCode == http.StatusForbidden && write:
				default:
					unexpected.Store(fmt.Sprintf("write %v: %d", write, resp.StatusCode), true)
				}
			}
		})
	}
	for round := range 6 {
		time.Sleep(100 * time.Millisecond)
		created := e.MustOverride(harness, permitOverride(store.OverrideException, "READER", "write-a", 600), `"r1"`, fmt.Sprintf("load-create-%02d-xxxx", round))
		withGrant[created.Generation] = true
		time.Sleep(100 * time.Millisecond)
		code, revoked, body := revokeOverride(e, harness, created.Override, fmt.Sprintf("load-revoke-%02d-xxxx", round))
		if code != http.StatusOK {
			t.Fatalf("revocation: %d %s", code, body)
		}
		withoutGrant[revoked.Generation] = true
	}
	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
	unexpected.Range(func(key, _ any) bool {
		t.Errorf("unexpected answer: %v", key)
		return true
	})
	writes, reads := 0, 0
	for _, r := range e.A.Receipts() {
		switch {
		case r.Method == http.MethodPost && withGrant[r.Generation] && r.Headers.Get("X-Gateway-Subject") == "bob":
			writes++
		case r.Method == http.MethodGet && (withGrant[r.Generation] || withoutGrant[r.Generation]):
			reads++
		default:
			t.Fatalf("A received %s by %s under generation %s", r.Method, r.Headers.Get("X-Gateway-Subject"), r.Generation)
		}
	}
	if writes == 0 || reads == 0 {
		t.Fatalf("traffic did not exercise both states: %d writes, %d reads", writes, reads)
	}
	t.Logf("forwarded %d: %d granted writes, %d reads", forwarded.Load(), writes, reads)
}
