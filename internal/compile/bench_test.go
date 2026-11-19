// Benchmarks of compiling a policy and of the per-request matching,
// authorisation, address and deadline checks.

package compile

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// benchPolicy has operations operations with body schemas, rates and
// permits on API a, and on API b browser access, a 256-range allow list and
// a host-conditioned operation beside its unconditioned sibling.
func benchPolicy(operations int) policy.Policy {
	p := policy.Policy{SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "u", Dial: "127.0.0.1:9000"}},
		APIs: []policy.API{{ID: "a", Upstream: "u"}, {ID: "b", Upstream: "u",
			CORS: &policy.CORS{Origins: []string{"https://shop.example"}, Methods: []string{"GET"}}}}}
	for i := range 256 {
		p.APIs[1].AllowAddresses = append(p.APIs[1].AllowAddresses, fmt.Sprintf("10.%d.0.0/16", i))
	}
	for i := range 32 {
		p.Roles = append(p.Roles, policy.Role{ID: fmt.Sprintf("r%d", i)})
	}
	schema := json.RawMessage(`{"type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string","maxLength":80},"price":{"type":"integer","minimum":1}}}`)
	for i := range operations {
		id := fmt.Sprintf("op%d", i)
		p.Operations = append(p.Operations, policy.Operation{ID: id, API: "a", Method: "POST", Target: fmt.Sprintf("/items/%d", i),
			Access: "allow", Auth: "required", Body: &policy.BodyRule{MaxBytes: 1024, Schema: schema},
			Rate: &policy.RateRule{Algorithm: "sliding-window", Count: 10, WindowSeconds: 60, Key: "subject"}})
		p.Permits = append(p.Permits, policy.Permit{Role: "r31", Operation: id})
	}
	p.Operations = append(p.Operations,
		policy.Operation{ID: "b.plain", API: "b", Method: "GET", Target: "/b/items/*", Access: "allow", Auth: "required"},
		policy.Operation{ID: "b.tenant", API: "b", Method: "GET", Target: "/b/items/*", Access: "allow", Auth: "required",
			When: &policy.When{Hosts: []string{"tenant.example"}}})
	p.Permits = append(p.Permits, policy.Permit{Role: "r31", Operation: "b.plain"}, policy.Permit{Role: "r31", Operation: "b.tenant"})
	return p
}

func benchGeneration(b *testing.B) *Generation {
	b.Helper()
	g, err := Compile(benchPolicy(200), 1, time.Time{}, policy.Limits{})
	if err != nil {
		b.Fatal(err)
	}
	return g
}

func BenchmarkCompile(b *testing.B) {
	p := benchPolicy(200)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Compile(p, 1, time.Time{}, policy.Limits{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCanonicalPath(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/items/12345/lines/7/details", nil)
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := CanonicalPath(r); !ok {
			b.Fatal("not canonical")
		}
	}
}

func BenchmarkMatch(b *testing.B) {
	g := benchGeneration(b)
	in := Inbound{Host: "other.example", Header: http.Header{}}
	b.ReportAllocs()
	for b.Loop() {
		if _, rule := g.Match("/b/items/42", http.MethodGet, in); rule == nil || rule.Operation() != "b.plain" {
			b.Fatal("no match")
		}
	}
}

func BenchmarkAuthorise(b *testing.B) {
	g := benchGeneration(b)
	_, rule := g.Match("/items/7", http.MethodPost, Inbound{})
	asserted := []string{"r1", "r2", "unknown", "r31"}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, reason := g.Authorise(asserted, rule); reason != "" {
			b.Fatal(reason)
		}
	}
}

func BenchmarkPreflight(b *testing.B) {
	g := benchGeneration(b)
	in := Inbound{Host: "other.example", Header: http.Header{}}
	b.ReportAllocs()
	for b.Loop() {
		if _, api := g.Preflight("/b/items/42", http.MethodGet, in); api == nil {
			b.Fatal("no preflight rule")
		}
	}
}

func BenchmarkAddressAllowed(b *testing.B) {
	g := benchGeneration(b)
	_, rule := g.Match("/b/items/42", http.MethodGet, Inbound{Header: http.Header{}})
	b.ReportAllocs()
	for b.Loop() {
		if !rule.AddressAllowed("10.255.3.4") {
			b.Fatal("refused")
		}
	}
}

func BenchmarkExpired(b *testing.B) {
	g := benchGeneration(b)
	b.ReportAllocs()
	for b.Loop() {
		if g.Lapsed() {
			b.Fatal("expired")
		}
	}
}

func BenchmarkRelabel(b *testing.B) {
	p := benchPolicy(200)
	g, err := Compile(p, 0, time.Time{}, policy.Limits{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		g.Relabel(7, nil)
	}
}
