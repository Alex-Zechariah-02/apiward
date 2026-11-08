// Override conflicts with a candidate policy.

package controller

import (
	"slices"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

// A candidate conflicts with an active override when it changes the
// override's own target, the operation it applies to or, for a permit, the
// role, or when it adds, moves or removes a more specific operation inside
// the override's path prefix. Anything else may proceed with the override in
// place.
func TestOverrideConflictWithCandidate(t *testing.T) {
	before := storetest.Protected()
	before.Operations[0].Rate = storetest.Rate(4, 60)
	overrides := []store.Override{
		{ID: 3, Type: store.OverrideException, Control: store.ControlPermit, Role: "READER", Operation: "write-a", Target: "permit:READER:write-a"},
		{ID: 4, Type: store.OverrideContainment, Control: store.ControlOperation, Operation: "read-b", Target: "operation:read-b"},
		{ID: 5, Type: store.OverrideException, Control: store.ControlRate, Operation: "read-a", Count: 9, Target: "rate:read-a"},
	}
	change := func(edit func(p *policy.Policy)) policy.Policy {
		p := before
		p.Operations = slices.Clone(before.Operations)
		p.Permits = slices.Clone(before.Permits)
		p.Roles = slices.Clone(before.Roles)
		edit(&p)
		return p
	}
	cases := []struct {
		name string
		edit func(p *policy.Policy)
		want int64 // conflicting override, 0 for none
	}{
		{"same permit granted permanently", func(p *policy.Policy) {
			p.Permits = append(p.Permits, policy.Permit{Role: "READER", Operation: "write-a"})
		}, 3},
		{"role of a permit override removed", func(p *policy.Policy) {
			p.Roles = p.Roles[1:] // READER
			p.Permits = slices.DeleteFunc(p.Permits, func(x policy.Permit) bool { return x.Role == "READER" })
		}, 3},
		{"operation of a permit override changed", func(p *policy.Policy) { p.Operations[1].Body = storetest.JSONBody(512, storetest.AnyObject) }, 3},
		{"operation of a permit override removed", func(p *policy.Policy) {
			p.Operations = slices.Delete(p.Operations, 1, 2)
			p.Permits = slices.DeleteFunc(p.Permits, func(x policy.Permit) bool { return x.Operation == "write-a" })
		}, 3},
		{"rate count changed", func(p *policy.Policy) { p.Operations[0].Rate = storetest.Rate(6, 60) }, 5},
		{"rate rule removed", func(p *policy.Policy) { p.Operations[0].Rate = nil }, 5},
		{"rate window changed", func(p *policy.Policy) { p.Operations[0].Rate = storetest.Rate(4, 120) }, 5},
		{"contained operation re-routed", func(p *policy.Policy) { p.Operations[3].Target = "/c/*" }, 4},
		{"contained operation denied permanently", func(p *policy.Policy) { p.Operations[3].Access = "deny" }, 4},
		{"more specific operation added inside a contained prefix", func(p *policy.Policy) {
			p.Operations = append(p.Operations, policy.Operation{ID: "special-b", API: "b", Method: "GET", Target: "/b/special", Access: "allow", Auth: "none"})
		}, 4},
		{"more specific prefix added inside an overridden prefix, other method", func(p *policy.Policy) {
			p.Operations = append(p.Operations, policy.Operation{ID: "deep-a", API: "a", Method: "DELETE", Target: "/a/deep/*", Access: "allow", Auth: "none"})
		}, 5},
		{"unrelated permit added", func(p *policy.Policy) {
			p.Permits = append(p.Permits, policy.Permit{Role: "WRITER", Operation: "read-b"})
		}, 0},
		{"unrelated permit removed", func(p *policy.Policy) {
			p.Permits = slices.DeleteFunc(p.Permits, func(x policy.Permit) bool { return x == policy.Permit{Role: "WRITER", Operation: "read-a"} })
		}, 0},
		{"unrelated operation re-routed outside every prefix", func(p *policy.Policy) { p.Operations[2].Target = "/dd" }, 0},
		{"rate rule added to an overridden operation, an independent control", func(p *policy.Policy) { p.Operations[1].Rate = storetest.Rate(9, 60) }, 0},
		{"less specific operation added above an overridden prefix", func(p *policy.Policy) {
			p.Operations = append(p.Operations, policy.Operation{ID: "all", API: "d", Method: "GET", Target: "/*", Access: "allow", Auth: "none"})
		}, 0},
		{"operation added beside a prefix, outside it", func(p *policy.Policy) {
			p.Operations = append(p.Operations, policy.Operation{ID: "bee", API: "b", Method: "GET", Target: "/bee", Access: "allow", Auth: "none"})
		}, 0},
		{"unrelated role added", func(p *policy.Policy) { p.Roles = append(p.Roles, policy.Role{ID: "OTHER"}) }, 0},
		{"nothing changed", func(p *policy.Policy) {}, 0},
	}
	for _, c := range cases {
		got := overrideConflict(before, change(c.edit), overrides)
		switch {
		case c.want == 0 && got != nil:
			t.Errorf("%s: conflicts with override %d", c.name, got.ID)
		case c.want != 0 && (got == nil || got.ID != c.want):
			t.Errorf("%s: %v, want override %d", c.name, got, c.want)
		}
	}
	if narrows("/a/item", "/a/item/x") || !narrows("/a/*", "/a/x") || narrows("/a/*", "/a/") || narrows("/a/*", "/ab") || !narrows("/*", "/a") {
		t.Error("narrows does not follow most-specific matching")
	}
}
