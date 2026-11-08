// Policies and trust settings tests build: a protected route, an upstream
// binding, header keywords, a rate rule and an extra subject.

package gatewaytest

import (
	"encoding/json"

	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// ProtectedPolicy is the standard test policy with authentication required on
// /a/*, /a/item and /b/*: READER may read /a/* and /b/*, WRITER may read and
// write /a/*. GET /d stays a denied public operation.
func (e *Env) ProtectedPolicy() policy.Policy {
	p := e.Policy(e.A, true)
	for i := range p.Operations {
		if p.Operations[i].ID != "denied" {
			p.Operations[i].Auth = "required"
		}
	}
	p.Roles = []policy.Role{{ID: "READER"}, {ID: "WRITER"}}
	p.Permits = []policy.Permit{
		{Role: "READER", Operation: "read-a"},
		{Role: "WRITER", Operation: "read-a"},
		{Role: "WRITER", Operation: "write-a"},
		{Role: "READER", Operation: "read-b"},
	}
	return p
}

// TestTrust trusts one issuer and audience with the single key "test-a" read
// from file.
func TestTrust(issuer, audience, file string) pipeline.TrustConfig {
	return pipeline.TrustConfig{Issuer: issuer, Audience: audience, Keys: []pipeline.VerificationKey{{Kid: "test-a", PublicKeyFile: file}}}
}

// PolicyWithUpstream adds operation GET /z, served by its own upstream.
func (e *Env) PolicyWithUpstream(dial string) policy.Policy {
	p := e.Policy(e.A, false)
	p.Upstreams = append(p.Upstreams, policy.Upstream{ID: "Z", Dial: dial})
	p.APIs = append(p.APIs, policy.API{ID: "z", Upstream: "Z"})
	p.Operations = append(p.Operations, policy.Operation{ID: "read-z", API: "z", Method: "GET", Target: "/z", Access: "allow", Auth: "none"})
	return p
}

// WithSubject is the JSON document of p with s as its only subject.
func WithSubject(p policy.Policy, s issuertest.Subject) json.RawMessage {
	var document map[string]any
	json.Unmarshal(MustJSON(p), &document)
	document["subjects"] = []issuertest.Subject{s}
	return MustJSON(document)
}

// Rate is a sliding-window rule of count requests per windowSeconds for each
// subject.
func Rate(count, windowSeconds int64) *policy.RateRule {
	return &policy.RateRule{Algorithm: "sliding-window", Count: count, WindowSeconds: windowSeconds, Key: "subject"}
}

// KeywordPolicy is the receiver test policy with a richer schema and header
// schema on POST /a/item, a header-only bodyless operation, and a large-body
// operation for decoder limits.
func (e *Env) KeywordPolicy() policy.Policy {
	p := e.Policy(e.A, false)
	for i := range p.Operations {
		if p.Operations[i].ID == "write-a" {
			p.Operations[i].Body = JSONBody(1024, `{"type":"object","additionalProperties":false,"required":["kind","count"],"properties":{`+
				`"kind":{"type":"string","enum":["alpha","beta"]},`+
				`"count":{"type":"integer","minimum":1,"maximum":5},`+
				`"note":{"type":["string","null"],"maxLength":8},`+
				`"meta":{"type":"object","additionalProperties":false,"properties":{"tag":{"type":"boolean"}}}}}`)
			p.Operations[i].Headers = json.RawMessage(`{"type":"object","additionalProperties":true,"required":["Idempotency-Key"],"properties":{` +
				`"Idempotency-Key":{"type":"string","minLength":8,"maxLength":64},"X-Mode":{"type":"string","enum":["safe","fast"]}}}`)
		}
	}
	p.Operations = append(p.Operations,
		policy.Operation{ID: "probe", API: "a", Method: "GET", Target: "/a/probe", Access: "allow", Auth: "none",
			Headers: json.RawMessage(`{"type":"object","additionalProperties":true,"required":["X-Probe"],"properties":{"X-Probe":{"type":"string","enum":["on"]}}}`)},
		policy.Operation{ID: "bulk", API: "a", Method: "POST", Target: "/a/bulk", Access: "allow", Auth: "none", Body: JSONBody(16000, AnyObject)},
	)
	return p
}
