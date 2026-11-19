// Benchmarks of policy decoding: a whole policy document, its member scan
// and a request body.

package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// benchPolicy is a policy document with operations operations, each with a
// body schema, a rate rule and a permit.
func benchPolicy(b *testing.B, operations int) []byte {
	b.Helper()
	p := Policy{SchemaVersion: SchemaVersion, Profile: ProfileCore,
		Upstreams: []Upstream{{ID: "u", Dial: "127.0.0.1:9000"}}, APIs: []API{{ID: "a", Upstream: "u"}},
		Roles: []Role{{ID: "reader"}, {ID: "writer"}}}
	schema := json.RawMessage(`{"type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string","maxLength":80},"price":{"type":"integer","minimum":1}}}`)
	for i := range operations {
		id := fmt.Sprintf("op%d", i)
		p.Operations = append(p.Operations, Operation{ID: id, API: "a", Method: "POST", Target: fmt.Sprintf("/items/%d", i),
			Access: "allow", Auth: "required", Body: &BodyRule{MaxBytes: 1024, Schema: schema},
			Rate: &RateRule{Algorithm: "sliding-window", Count: 10, WindowSeconds: 60, Key: "subject"}})
		p.Permits = append(p.Permits, Permit{Role: "writer", Operation: id})
	}
	document, err := json.Marshal(p)
	if err != nil {
		b.Fatal(err)
	}
	return document
}

func BenchmarkDecodePolicy(b *testing.B) {
	document := benchPolicy(b, 100)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodePolicy(document, Limits{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckMembers(b *testing.B) {
	document := benchPolicy(b, 100)
	b.ReportAllocs()
	for b.Loop() {
		if err := CheckMembers(document, MaxPolicyDepth); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeJSON(b *testing.B) {
	lines := make([]string, 0, 20)
	for i := range 20 {
		lines = append(lines, fmt.Sprintf(`{"sku":"A-%d","qty":%d,"price":1.5e3,"note":"caf\u00e9","tags":["x","y"]}`, i, i))
	}
	body := []byte(`{"order":{"customer":{"id":"c-1","address":{"city":"Kuching"}},"lines":[` + strings.Join(lines, ",") + `]}}`)
	b.ReportAllocs()
	for b.Loop() {
		if _, reason := DecodeJSON(body); reason != "" {
			b.Fatal(reason)
		}
	}
}
