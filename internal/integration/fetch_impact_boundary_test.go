// Fetch impact previews: request targets, independent controls, access
// grants and identity coverage.

package integration

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func TestFetchImpactPreservesRequestTarget(t *testing.T) {
	truncated := "/a/" + strings.Repeat("x", audit.MaxLoggedPath-3)
	for _, tc := range []struct {
		name, path string
		status     int
	}{
		{"long-path", truncated + "/tail", 200},
		{"encoded-separator", "/a/part%2Ftail", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			draft := e.Policy(e.A, false)
			gatewaytest.Seed(t, e.Database, draft, gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Plain)
			admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			if code, _ := e.Get(tc.path); code != tc.status {
				t.Fatalf("original request: %d, want %d", code, tc.status)
			}
			if tc.name == "long-path" {
				// The displayed 256-byte path happens to be an exact target, but
				// the actual longer request still belongs to the unchanged prefix.
				draft.Operations = append(draft.Operations, policy.Operation{ID: "exact", API: "a", Method: "GET", Target: truncated, Access: "deny", Auth: "none"})
			} else {
				// A fixed raw-target rejection cannot be lifted by a policy change.
				draft.Operations[0].Access = "deny"
			}
			code, staged, body := e.Stage(admin, draft, `"r1"`, "impact-target-candidate")
			if code != 201 {
				t.Fatalf("stage: %d %s", code, body)
			}
			code, body, _ = e.As(admin, "POST", fmt.Sprintf("/admin/candidates/%d/impact", staged.Candidate.ID), "")
			var impact struct {
				Flips []json.RawMessage `json:"flips"`
			}
			if code != 200 || json.Unmarshal([]byte(body), &impact) != nil || len(impact.Flips) != 0 {
				t.Errorf("preview changed the request target's meaning: %d %s", code, body)
			}
			if code, _, body = e.Activate(admin, staged.Candidate.CandidateRecord, 60, `"r1"`, "impact-target-activate"); code != 200 {
				t.Fatalf("activate: %d %s", code, body)
			}
			if code, _ := e.Get(tc.path); code != tc.status {
				t.Fatalf("actual request after activation: %d, want %d", code, tc.status)
			}
			arrivals := 0
			if tc.status == 200 {
				arrivals = 2
			}
			e.AssertReceipts(arrivals, 0, 0)
		})
	}
}

func TestFetchImpactPreservesIndependentControls(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocked_%t", blocked), func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			draft := e.ProtectedPolicy()
			gatewaytest.Seed(t, e.Database, draft, gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Plain)
			admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			if blocked {
				if code, _, body := blockAccount(e, admin, "alice", "independent containment", "impact-independent-block"); code != 200 {
					t.Fatalf("block: %d %s", code, body)
				}
				if code, _ := e.Get("/a/independent", gatewaytest.Bearer(t, "alice")...); code != 403 {
					t.Fatalf("blocked probe: %d", code)
				}
				draft = withoutRole(draft, "WRITER")
			} else {
				e.MustOverride(admin, permitOverride(store.OverrideException, "READER", "write-a", 60), `"r1"`, "impact-independent-override")
				if code, _ := e.Request("POST", "/a/item", "application/json", `{"n":1}`, gatewaytest.Bearer(t, "bob")...); code != 200 {
					t.Fatalf("override probe: %d", code)
				}
				draft.Roles = append(draft.Roles, policy.Role{ID: "OTHER"})
			}
			code, staged, body := e.Stage(admin, draft, `"r1"`, "impact-independent-candidate")
			if code != 201 {
				t.Fatalf("stage: %d %s", code, body)
			}
			before := e.Status()
			code, body, _ = e.As(admin, "POST", fmt.Sprintf("/admin/candidates/%d/impact", staged.Candidate.ID), "")
			var impact struct {
				Flips []json.RawMessage `json:"flips"`
			}
			if code != 200 || json.Unmarshal([]byte(body), &impact) != nil || len(impact.Flips) != 0 {
				t.Errorf("preview lost an independent control: %d %s", code, body)
			}
			if after := e.Status(); after.Generation != before.Generation || after.Revision != before.Revision {
				t.Fatal("preview changed authority")
			}
			code, _, body = e.Activate(admin, staged.Candidate.CandidateRecord, 60, `"r1"`, "impact-independent-activate")
			if code != 200 {
				t.Fatalf("actual activation: %d %s", code, body)
			}
			if blocked {
				if code, _ := e.Get("/a/independent", gatewaytest.Bearer(t, "alice")...); code != 403 {
					t.Fatalf("actual blocked decision: %d", code)
				}
			} else {
				if code, _ := e.Request("POST", "/a/item", "application/json", `{"n":1}`, gatewaytest.Bearer(t, "bob")...); code != 200 {
					t.Fatalf("actual overridden decision: %d", code)
				}
			}
		})
	}
}

func TestFetchImpactAccessGrantHasKnownOutcome(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.ProtectedPolicy()
	p.Operations[0].Access = "deny"
	gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	if code, _ := e.Get("/a/access-preview", gatewaytest.Bearer(t, "alice")...); code != 403 {
		t.Fatalf("denied baseline: %d", code)
	}
	p.Operations[0].Access = "allow"
	code, staged, body := e.Stage(admin, p, `"r1"`, "impact-access-candidate")
	if code != 201 {
		t.Fatalf("stage: %d %s", code, body)
	}
	code, body, _ = e.As(admin, "POST", fmt.Sprintf("/admin/candidates/%d/impact", staged.Candidate.ID), "")
	var impact struct {
		Window struct {
			Requests, Previewed int
			IdentityUnknown     int `json:"identity_unknown"`
		} `json:"window"`
		Flips []struct {
			Before, After string
			Count         int
		} `json:"flips"`
		NotPreviewed []string `json:"not_previewed"`
	}
	// The token was not evaluated before the access refusal. The preview must
	// disclose that uncertainty rather than guess an authentication result.
	if code != 200 || json.Unmarshal([]byte(body), &impact) != nil || impact.Window.Requests != 1 || impact.Window.Previewed != 0 || impact.Window.IdentityUnknown != 1 || len(impact.Flips) != 0 || !slices.Equal(impact.NotPreviewed, []string{"rate", "body", "unobserved_identity"}) {
		t.Errorf("preview did not disclose unobserved identity: %d %s", code, body)
	}
	code, activation, body := e.Activate(admin, staged.Candidate.CandidateRecord, 60, `"r1"`, "impact-access-activate")
	if code != 200 {
		t.Fatalf("activate: %d %s", code, body)
	}
	if code, _, body := e.Resolve(admin, "confirm", activation.Provisional, `"r1"`, "impact-access-confirm"); code != 200 {
		t.Fatalf("confirm: %d %s", code, body)
	}
	if code, _ := e.Get("/a/access-preview", gatewaytest.Bearer(t, "alice")...); code != 200 {
		t.Fatalf("actual decision after grant: %d", code)
	}
	e.AssertReceipts(1, 0, 0)
}

func TestFetchImpactIdentityCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, auth, access, credential, afterAuth string
		unknown, flips, actual                    int
	}{
		{"absent-before-access", "required", "deny", "", "required", 0, 0, 401},
		{"unread-public-token", "none", "allow", "valid", "required", 1, 0, 200},
		{"anonymous-public", "none", "allow", "", "required", 0, 1, 401},
		{"no-identity-needed", "required", "deny", "valid", "none", 0, 1, 200},
		{"invalid-identity-observed", "required", "allow", "invalid", "none", 0, 1, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			draft := e.ProtectedPolicy()
			draft.Operations[0].Auth, draft.Operations[0].Access = tc.auth, tc.access
			if tc.auth == "none" {
				draft.Permits = slices.DeleteFunc(draft.Permits, func(p policy.Permit) bool { return p.Operation == "read-a" })
			}
			gatewaytest.Seed(t, e.Database, draft, gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Plain)
			admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
			headers := []string{}
			if tc.credential == "valid" {
				headers = gatewaytest.Bearer(t, "alice")
			} else if tc.credential == "invalid" {
				headers = []string{"Authorization", "Bearer invalid"}
			}
			e.Get("/a/identity-coverage", headers...)
			candidate := e.ProtectedPolicy()
			candidate.Operations[0].Auth = tc.afterAuth
			if tc.afterAuth == "none" {
				candidate.Permits = slices.DeleteFunc(candidate.Permits, func(p policy.Permit) bool { return p.Operation == "read-a" })
			}
			code, staged, body := e.Stage(admin, candidate, `"r1"`, "impact-coverage-candidate")
			if code != 201 {
				t.Fatalf("stage: %d %s", code, body)
			}
			code, body, _ = e.As(admin, "POST", fmt.Sprintf("/admin/candidates/%d/impact", staged.Candidate.ID), "")
			var result struct {
				Window struct {
					Requests, Previewed int
					IdentityUnknown     int `json:"identity_unknown"`
				} `json:"window"`
				Flips        []json.RawMessage `json:"flips"`
				NotPreviewed []string          `json:"not_previewed"`
			}
			if code != 200 || json.Unmarshal([]byte(body), &result) != nil || result.Window.Requests != 1 || result.Window.IdentityUnknown != tc.unknown || result.Window.Previewed != 1-tc.unknown || len(result.Flips) != tc.flips || slices.Contains(result.NotPreviewed, "unobserved_identity") != (tc.unknown > 0) {
				t.Errorf("coverage: %d %s", code, body)
			}
			code, _, body = e.Activate(admin, staged.Candidate.CandidateRecord, 60, `"r1"`, "impact-coverage-activate")
			if code != 200 {
				t.Fatalf("activate: %d %s", code, body)
			}
			if code, _ := e.Get("/a/identity-coverage", headers...); code != tc.actual {
				t.Fatalf("actual decision: %d, want %d", code, tc.actual)
			}
		})
	}
}
