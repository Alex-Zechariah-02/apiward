// Policy decoding bounds checked at their exact values: the document size.

package policy

import (
	"errors"
	"testing"
)

// A document of exactly the configured policy_bytes is decoded; one byte
// over is refused as too large.
func TestPolicyBytesAtBound(t *testing.T) {
	document := []byte(`{"schema_version":4,"profile":"core","upstreams":[{"id":"A","dial":"127.0.0.1:9"}],"apis":[{"id":"a","upstream":"A"}],` +
		`"operations":[{"id":"x","api":"a","method":"GET","target":"/a/x","access":"allow","auth":"none"}],"roles":[],"permits":[]}`)
	if _, err := DecodePolicy(document, Limits{PolicyBytes: len(document)}); err != nil {
		t.Fatalf("document of exactly %d bytes: %v", len(document), err)
	}
	_, err := DecodePolicy(document, Limits{PolicyBytes: len(document) - 1})
	if refused, ok := errors.AsType[*PolicyError](err); !ok || refused.Code != "POLICY_TOO_LARGE" {
		t.Fatalf("document over the bound by one byte: %v, want POLICY_TOO_LARGE", err)
	}
}
