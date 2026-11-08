// Role changes, swaps, refusals and crashes.

package integration

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// A role removal published while a request is in flight does not change that
// request: it completes under the generation it captured, with that
// generation's roles. Every later request uses the new generation. The held
// request is paused right after capture, before authentication and
// authorisation run, so both run after the new generation is published.
func TestRoleChangeAppliesToNewRequestsOnly(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	holdFile, release := filepath.Join(e.Dir, "hold"), filepath.Join(e.Dir, "release")
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_HOLD_PATH=/a/item", "GATEWAY_HOLD_FILE="+holdFile, "GATEWAY_HOLD_RELEASE="+release)
	first := e.Status().Generation
	aliceToken, bobToken := gatewaytest.Issuer.TokenFor(t, "alice"), gatewaytest.Issuer.TokenFor(t, "bob")

	conn, captured := holdRequest(t, e, holdFile, aliceToken)
	defer conn.Close()
	if captured != first {
		t.Fatalf("captured %s, want %s", captured, first)
	}

	// The next generation removes alice's role and grants READER the write.
	next := withoutRole(e.ProtectedPolicy(), "WRITER")
	next.Permits = append(next.Permits, policy.Permit{Role: "READER", Operation: "write-a"})
	outcome, code := e.Publish(controller.Change{ID: "remove-writer", Expected: 1, Policy: gatewaytest.MustJSON(next)})
	if code != http.StatusOK {
		t.Fatalf("publish: %d %+v", code, outcome)
	}

	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "true}")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("in-flight request: %v %v", resp, err)
	}
	e.AssertReceipts(1, 0, 0)
	held := e.A.Receipts()[0]
	if held.Generation != first || held.Headers.Get("X-Gateway-Roles") != "WRITER" {
		t.Fatalf("in-flight request reached A under %s with roles %q, want %s and WRITER", held.Generation, held.Headers.Get("X-Gateway-Roles"), first)
	}

	// New requests: alice is refused without reaching A; bob now may write.
	resp, body := e.Exchange(http.MethodPost, "/a/item", "application/json", `{"n":1}`, "Authorization", "Bearer "+aliceToken)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice after removal: %d %s", resp.StatusCode, body)
	}
	e.AssertReceipts(1, 0, 0)
	_, refusedID := gatewaytest.RequestID(resp, body)
	if code, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":2}`, "Authorization", "Bearer "+bobToken); code != http.StatusOK {
		t.Fatalf("bob after the new permit: %d", code)
	}
	e.AssertReceipts(2, 0, 0)
	if g := e.A.Receipts()[1].Generation; g != outcome.Generation {
		t.Fatalf("bob's write under %s, want %s", g, outcome.Generation)
	}

	events := e.EventsWhen(func(events []map[string]any) bool {
		return gatewaytest.CountKind(events, "request.forwarded") == 2 && gatewaytest.FindEvent(events, "request.rejected", refusedID) != nil
	})
	if ev := gatewaytest.FindEvent(events, "request.forwarded", held.RequestID); ev == nil || ev["generation"] != first || ev["subject"] != "alice" {
		t.Fatalf("in-flight event %v", ev)
	}
	if ev := gatewaytest.FindEvent(events, "request.rejected", refusedID); ev == nil || ev["generation"] != outcome.Generation || ev["reason"] != "no_permit" {
		t.Fatalf("refusal event %v", ev)
	}
}

// While membership changes repeatedly under concurrent load, every decision
// matches the generation it was made under: a request reaches the upstream
// only under a generation in which the caller holds a permitted role, and a
// refusal happens only under one in which it does not.
func TestRoleSwapsUnderLoad(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault)
	bobToken := gatewaytest.Issuer.TokenFor(t, "bob")

	// Whether bob may read /a/* under each generation.
	permitted := map[string]bool{e.Status().Generation: true}

	const workers = 8
	const swaps = 100
	requests := make(chan struct{}, workers)
	completed := make(chan struct{}, workers)
	var unexpected atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			client := &http.Client{Timeout: 10 * time.Second}
			for range requests {
				req, _ := http.NewRequest(http.MethodGet, "http://"+e.DataAddr+"/a/x", nil)
				req.Header.Set("Authorization", "Bearer "+bobToken)
				resp, err := client.Do(req)
				if err != nil {
					e.T.Logf("role-swap request failed: %v", err)
					unexpected.Add(1)
					completed <- struct{}{}
					continue
				}
				_, readErr := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if readErr != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden) {
					e.T.Logf("role-swap response: status=%d read=%v", resp.StatusCode, readErr)
					unexpected.Add(1)
				}
				completed <- struct{}{}
			}
		})
	}
	defer func() {
		close(requests)
		wg.Wait()
	}()

	for i := range swaps {
		bobRoles := []string{"READER"}
		if i%2 == 0 {
			bobRoles = nil
		}
		policy := e.ProtectedPolicy()
		if bobRoles == nil {
			policy = withoutRole(policy, "READER")
		}
		// Keep eight real requests racing every publication, with an exact
		// bound. An unbounded refusal loop exhausts Windows client ports
		// because the gateway deliberately closes refused connections.
		for range workers {
			requests <- struct{}{}
		}
		outcome, code := e.Publish(controller.Change{ID: fmt.Sprintf("swap-%d", i), Expected: int64(i + 1), Policy: gatewaytest.MustJSON(policy)})
		if code != http.StatusOK {
			t.Fatalf("swap %d: %d %+v", i, code, outcome)
		}
		permitted[outcome.Generation] = bobRoles != nil
		for range workers {
			<-completed
		}
	}
	if unexpected.Load() != 0 {
		t.Fatalf("%d requests failed or got an unexpected status", unexpected.Load())
	}

	forwarded := 0
	for _, r := range e.A.Receipts() {
		if !permitted[r.Generation] || r.Headers.Get("X-Gateway-Roles") != "READER" {
			t.Fatalf("receipt under %s with roles %q, where bob holds no permitted role", r.Generation, r.Headers.Get("X-Gateway-Roles"))
		}
		forwarded++
	}
	events := e.EventsWhen(func(events []map[string]any) bool {
		return gatewaytest.CountKind(events, "request.forwarded")+gatewaytest.CountKind(events, "request.rejected") >= workers*swaps
	})
	refused := 0
	for _, ev := range events {
		if ev["kind"] != "request.rejected" {
			continue
		}
		generation, _ := ev["generation"].(string)
		if ev["reason"] != "no_permit" || permitted[generation] {
			t.Fatalf("refusal %v under a generation in which bob is permitted", ev)
		}
		refused++
	}
	t.Logf("%d swaps: %d requests reached the upstream, %d refused, each under the right generation", swaps, forwarded, refused)
	if forwarded == 0 || refused == 0 {
		t.Fatal("the load did not exercise both outcomes")
	}
	if forwarded+refused != workers*swaps {
		t.Fatalf("%d receipts plus %d refusals, want %d decisions", forwarded, refused, workers*swaps)
	}
}

// A membership change that is invalid or based on a stale revision is
// refused as a whole; the previous membership keeps applying.
func TestRejectedRoleChangeKeepsMembership(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault)
	before := e.Status()
	aliceToken := gatewaytest.Issuer.TokenFor(t, "alice")

	removal := withoutRole(e.ProtectedPolicy(), "WRITER")
	invalid := e.ProtectedPolicy()
	invalid.Permits = append(invalid.Permits, policy.Permit{Role: "ADMIN", Operation: "write-a"})
	duplicate := e.ProtectedPolicy()
	duplicate.Roles = append(duplicate.Roles, policy.Role{ID: "READER"})
	changes := []struct {
		change controller.Change
		status int
		reason string
	}{
		{controller.Change{ID: "unknown-role", Expected: 1, Policy: gatewaytest.MustJSON(invalid)}, 400, "UNKNOWN_REFERENCE"},
		{controller.Change{ID: "duplicate-subject", Expected: 1, Policy: gatewaytest.MustJSON(duplicate)}, 400, "DUPLICATE_ID"},
		{controller.Change{ID: "stale-removal", Expected: 0, Policy: gatewaytest.MustJSON(removal)}, 409, "STALE"},
	}
	for _, c := range changes {
		outcome, code := e.Publish(c.change)
		if code != c.status || outcome.Reason != c.reason {
			t.Errorf("%s: %d %+v, want %d %s", c.change.ID, code, outcome, c.status, c.reason)
		}
		if s := e.Status(); s.Generation != before.Generation {
			t.Fatalf("%s changed the generation", c.change.ID)
		}
		if code, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":1}`, "Authorization", "Bearer "+aliceToken); code != http.StatusOK {
			t.Fatalf("alice after rejected %s: %d", c.change.ID, code)
		}
	}

	// The valid removal then applies.
	if _, code := e.Publish(controller.Change{ID: "disable-alice", Expected: 1, Policy: gatewaytest.MustJSON(removal)}); code != http.StatusOK {
		t.Fatalf("valid removal: %d", code)
	}
	if code, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":1}`, "Authorization", "Bearer "+aliceToken); code != http.StatusForbidden {
		t.Fatalf("disabled alice: %d", code)
	}
	e.AssertReceipts(len(changes), 0, 0)
}

// A crash during a membership publication leaves either the old or the new
// membership in force after restart, never a mixture, and the transition is
// applied exactly once.
func TestRoleChangeSurvivesCrash(t *testing.T) {
	for _, tc := range []struct {
		point     string
		committed bool
	}{
		{"before-commit", false},
		{"after-commit", true},
		{"after-swap", true},
	} {
		t.Run(tc.point, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT="+tc.point)
			aliceToken, bobToken := gatewaytest.Issuer.TokenFor(t, "alice"), gatewaytest.Issuer.TokenFor(t, "bob")

			// Removes WRITER from policy and grants READER the write.
			next := withoutRole(e.ProtectedPolicy(), "WRITER")
			next.Permits = append(next.Permits, policy.Permit{Role: "READER", Operation: "write-a"})
			change := controller.Change{ID: "swap-roles", Expected: 1, Policy: gatewaytest.MustJSON(next)}
			if _, code := e.Publish(change); code != 0 {
				t.Fatalf("publication answered %d instead of crashing", code)
			}
			if code := e.WaitExit(); code != crashExit {
				t.Fatalf("exit code %d, want %d\n%s", code, crashExit, e.Output)
			}

			e.Start(gatewaytest.Binaries.Fault)
			wantAlice, wantBob, wantRevision := http.StatusOK, http.StatusForbidden, int64(1)
			if tc.committed {
				wantAlice, wantBob, wantRevision = http.StatusForbidden, http.StatusOK, 2
			}
			if s := e.Status(); s.Revision != wantRevision {
				t.Fatalf("restart serves revision %d, want %d", s.Revision, wantRevision)
			}
			aliceCode, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":1}`, "Authorization", "Bearer "+aliceToken)
			bobCode, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":2}`, "Authorization", "Bearer "+bobToken)
			if aliceCode != wantAlice || bobCode != wantBob {
				t.Fatalf("after restart alice %d bob %d, want %d %d", aliceCode, bobCode, wantAlice, wantBob)
			}
			e.AssertReceipts(1, 0, 0)

			// Retrying the same transition applies it exactly once.
			if outcome, code := e.Publish(change); code != http.StatusOK || outcome.Revision != 2 {
				t.Fatalf("retry: %d %+v", code, outcome)
			}
			if code, _ := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":3}`, "Authorization", "Bearer "+aliceToken); code != http.StatusForbidden {
				t.Fatalf("alice after retry: %d", code)
			}
		})
	}
}
