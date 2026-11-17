// Control changes between two policies.

package compile

import (
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// A change to an API's own settings (here its client address allow list)
// is reported as a change of that API, not only a change of its upstream.
func TestAPISettingsChange(t *testing.T) {
	before := policy.Policy{APIs: []policy.API{{ID: "a", Upstream: "u"}}}
	after := policy.Policy{APIs: []policy.API{{ID: "a", Upstream: "u", AllowAddresses: []string{"10.0.0.0/8"}}}}
	changes := PolicyChanges(before, after)
	if len(changes) != 1 || changes[0] != (ControlChange{"api", "a"}) {
		t.Fatalf("changes = %v, want [{api a}]", changes)
	}
	// An order enforcement ignores is no change: a list inside an API, or a
	// schema's members (which would refuse a publication under an override).
	ordered := func(ranges []string, schema string) policy.Policy {
		return policy.Policy{
			APIs:       []policy.API{{ID: "a", Upstream: "u", AllowAddresses: ranges}},
			Operations: []policy.Operation{{ID: "o", API: "a", Body: &policy.BodyRule{Schema: []byte(schema)}}},
		}
	}
	if changes := PolicyChanges(
		ordered([]string{"10.0.0.0/8", "192.168.0.0/16"}, `{"type":"object","maxProperties":2}`),
		ordered([]string{"192.168.0.0/16", "10.0.0.0/8"}, `{"maxProperties":2,"type":"object"}`),
	); len(changes) != 0 {
		t.Fatalf("re-ordered lists and members reported as %v", changes)
	}
}
