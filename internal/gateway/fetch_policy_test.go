// The version a Fetch policy document declares.

package gateway

import (
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// Rejecting v4 here prevents a fresh Fetch deployment from activating at all.
func TestFetchPolicyVersion4(t *testing.T) {
	const document = `{
		"schema_version":4,"profile":"core",
		"upstreams":[{"id":"inventory-svc","dial":"127.0.0.1:10501"}],
		"apis":[{"id":"inventory","upstream":"inventory-svc"}],
		"operations":[{"id":"inventory.search","api":"inventory","method":"GET",
			"target":"/inventory/search","access":"allow","auth":"none",
			"rate":{"algorithm":"sliding-window","count":60,"window_seconds":60,"key":"client_address"}}],
		"roles":[{"id":"CUSTOMER"}],"permits":[]
	}`
	policy, err := policy.DecodePolicy([]byte(document))
	if err != nil {
		t.Fatalf("Fetch v4 policy must decode: %v", err)
	}
	generation, err := compile.Compile(policy, 1, time.Time{})
	if err != nil {
		t.Fatalf("public client-address rate must compile: %v", err)
	}
	_, operation := generation.Match("/inventory/search", "GET", compile.Inbound{})
	if operation == nil || !operation.Public() || !operation.Permitted() || operation.Rate() == nil {
		t.Fatalf("compiled public search lost its controls: %+v", operation)
	}
}
