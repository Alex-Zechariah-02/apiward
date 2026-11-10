// Policy count checks against the deployment's capacity limits.

package compile

import (
	"errors"
	"fmt"
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
