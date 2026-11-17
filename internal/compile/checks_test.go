// Policy count checks against the deployment's capacity limits, the deny-all
// test, publication warnings, repeated question headers and the preflight
// rate rule's choice.

package compile

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// A policy one operation over the default ceiling is refused at the default
// and compiles when the deployment raises the ceiling.
func TestCountLimits(t *testing.T) {
	p := policy.Policy{SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "u", Dial: "127.0.0.1:9000"}}, APIs: []policy.API{{ID: "a", Upstream: "u"}}}
	for i := range policy.DefaultOperations + 1 {
		p.Operations = append(p.Operations, policy.Operation{ID: fmt.Sprintf("op%d", i), API: "a", Method: "GET",
			Target: fmt.Sprintf("/op%d", i), Access: "deny", Auth: "required"})
	}
	_, err := Compile(p, 1, time.Time{}, policy.Limits{})
	if refused, ok := errors.AsType[*policy.PolicyError](err); !ok || refused.Code != "LIMIT_EXCEEDED" || refused.Field != "operations" {
		t.Fatalf("at the default: %v, want LIMIT_EXCEEDED at operations", err)
	}
	if _, err := Compile(p, 1, time.Time{}, policy.Limits{Operations: policy.DefaultOperations + 1}); err != nil {
		t.Fatalf("with the raised ceiling: %v", err)
	}
}

// A permit on an operation whose access is deny admits nothing, so the policy
// stays deny-all; a permit on an allowed operation does not.
func TestDenyAllCountsAllowedPermits(t *testing.T) {
	p := policy.Policy{
		Operations: []policy.Operation{{ID: "x", Access: "deny"}, {ID: "y", Access: "deny"}},
		Permits:    []policy.Permit{{Role: "R", Operation: "x"}},
	}
	if !DenyAll(p) {
		t.Fatal("a permit on a denied operation made the policy admit traffic")
	}
	p.Operations[0].Access = "allow"
	if DenyAll(p) {
		t.Fatal("a permit on an allowed operation was not counted")
	}
}

// The compiler warns of a prefix target without its exact path and of plain
// http to an address other than loopback, and of nothing else.
func TestWarnings(t *testing.T) {
	g, err := Compile(policy.Policy{
		SchemaVersion: policy.LatestSchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "near", Dial: "127.0.0.1:9"}, {ID: "far", URL: "http://192.0.2.10:9"}},
		APIs:      []policy.API{{ID: "a", Upstream: "near"}, {ID: "b", Upstream: "far"}},
		Operations: []policy.Operation{
			{ID: "alone", API: "a", Method: "GET", Target: "/a/*", Access: "deny", Auth: "none"},
			{ID: "paired", API: "a", Method: "GET", Target: "/p/*", Access: "deny", Auth: "none"},
			{ID: "pair", API: "a", Method: "GET", Target: "/p", Access: "deny", Auth: "none"},
			{ID: "far", API: "b", Method: "GET", Target: "/b", Access: "deny", Auth: "none"},
		},
	}, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	warnings := g.Warnings()
	if len(warnings) != 2 || !strings.HasPrefix(warnings[0], "target /a/* ") || !strings.HasPrefix(warnings[1], "upstreams[1].url ") {
		t.Fatalf("warnings %q", warnings)
	}
}

// Header names that differ only in letter case are one header, so a question
// naming both is refused rather than answered from either.
func TestQuestionRepeatedHeader(t *testing.T) {
	if _, field := NewQuestion("GET", "/a", "", map[string]string{"X-Tenant": "a", "x-tenant": "b"}, nil); field != "headers" {
		t.Fatalf("refused field %q, want headers", field)
	}
}

// The first public operation decides an API's preflight rule: without a rate
// of its own, preflights are not counted, even when a later one has a rate.
func TestPreflightRateFirstPublic(t *testing.T) {
	counted := &policy.RateRule{Algorithm: "sliding-window", Count: 4, WindowSeconds: 60, Key: "client_address"}
	g, err := Compile(policy.Policy{
		SchemaVersion: policy.LatestSchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "u", Dial: "127.0.0.1:9"}},
		APIs:      []policy.API{{ID: "a", Upstream: "u"}},
		Operations: []policy.Operation{
			{ID: "plain", API: "a", Method: "GET", Target: "/plain", Access: "allow", Auth: "none"},
			{ID: "counted", API: "a", Method: "GET", Target: "/counted", Access: "allow", Auth: "none", Rate: counted},
		},
	}, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range g.Rules() {
		if limit := rule.PreflightRate(); limit != nil {
			t.Fatalf("%s: preflight rule %+v, want none (the first public operation has no rate)", rule.Operation(), limit)
		}
	}
}
