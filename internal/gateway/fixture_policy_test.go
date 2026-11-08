// Fixture policy and catalogue agreement.

package gateway

import (
	"slices"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// The hand-written gateway policy agrees with the independent catalogue on
// every operation, permit and subject, and the catalogue's role truth
// distinguishes profiles.
func TestPolicyAgreesWithCatalogue(t *testing.T) {
	c := gatewaytest.LoadCatalogue(t)
	p := gatewaytest.FixturePolicy(map[string]*gatewaytest.FixtureProcess{
		"orders": {Addr: "127.0.0.1:1"}, "inventory": {Addr: "127.0.0.1:2"}, "reports": {Addr: "127.0.0.1:3"},
	})
	if _, err := compile.Compile(p, 1, time.Time{}); err != nil {
		t.Fatalf("fixture policy does not compile: %v", err)
	}

	roles := map[string][]string{}
	for _, permit := range p.Permits {
		roles[permit.Operation] = append(roles[permit.Operation], permit.Role)
	}
	operations := map[string]policy.Operation{}
	for _, op := range p.Operations {
		operations[op.ID] = op
	}
	if len(operations) != len(c.Operations) {
		t.Fatalf("policy has %d operations, catalogue %d", len(operations), len(c.Operations))
	}

	differing := 0
	for _, want := range c.Operations {
		got, ok := operations[want.ID]
		apiOK := ok && got.API == want.API && got.Method == want.Method && got.Target == want.Target
		if !apiOK || got.Auth != want.Auth || (got.Body != nil) != want.Body {
			t.Errorf("operation %s: policy %+v, catalogue %+v", want.ID, got, want)
		}
		gotRoles := slices.Sorted(slices.Values(roles[want.ID]))
		wantRoles := slices.Sorted(slices.Values(want.Roles))
		if !slices.Equal(gotRoles, wantRoles) {
			t.Errorf("operation %s: policy permits %v, catalogue truth %v", want.ID, gotRoles, wantRoles)
		}
		if len(want.Roles) > 0 && len(want.Roles) < len(c.Roles) {
			differing++
		}
	}
	if differing == 0 {
		t.Fatal("no operation distinguishes role profiles")
	}
	if !slices.Equal(slices.Sorted(slices.Values(c.Roles)), []string{"CUSTOMER", "MANAGER", "STAFF"}) {
		t.Fatalf("catalogue roles %v", c.Roles)
	}

	for _, want := range c.Subjects {
		gotRoles := issuertest.Roles(want.ID)
		wantRoles := slices.Sorted(slices.Values(want.Roles))
		if !slices.Equal(gotRoles, wantRoles) {
			t.Errorf("subject %s: issuer %v, catalogue %+v", want.ID, gotRoles, want)
		}
	}
	t.Logf("catalogue %s: %d operations, %d distinguish role profiles, %d subjects, %d scenarios",
		c.Version, len(c.Operations), differing, len(c.Subjects), len(c.Scenarios))
}
