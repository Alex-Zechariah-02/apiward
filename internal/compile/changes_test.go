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
}
