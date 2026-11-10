// Rate rule compilation.

package gateway

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// Rate rules compile only with a supported algorithm and key, a positive
// bounded count and window, and a per-account key only on an authenticated
// operation. Any invalid rule rejects the whole policy.
func TestRateRuleCompilation(t *testing.T) {
	p := threeAPIPolicy()
	p.Operations[0].Rate = gatewaytest.Rate(10, 60)
	g, err := compile.Compile(p, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatalf("valid rate rule rejected: %v", err)
	}
	_, r := g.Match("/orders", "GET", compile.Inbound{})
	if r.Rate() == nil || r.Rate().Count() != 10 || r.Rate().Window() != 60000 {
		t.Fatalf("compiled rule %+v", r.Rate())
	}
	if _, other := g.Match("/orders/1", "GET", compile.Inbound{}); other.Rate() != nil {
		t.Fatal("a rate rule applied to an operation that does not declare one")
	}

	cases := []struct {
		name  string
		rule  policy.RateRule
		code  string
		field string
	}{
		{"zero count", policy.RateRule{Algorithm: "sliding-window", Count: 0, WindowSeconds: 60, Key: "subject"}, "INVALID_VALUE", "operations[0].rate.count"},
		{"negative count", policy.RateRule{Algorithm: "sliding-window", Count: -1, WindowSeconds: 60, Key: "subject"}, "INVALID_VALUE", "operations[0].rate.count"},
		{"count above the bound", policy.RateRule{Algorithm: "sliding-window", Count: compile.MaxRateCount + 1, WindowSeconds: 60, Key: "subject"}, "INVALID_VALUE", "operations[0].rate.count"},
		{"zero window", policy.RateRule{Algorithm: "sliding-window", Count: 10, WindowSeconds: 0, Key: "subject"}, "INVALID_VALUE", "operations[0].rate.window_seconds"},
		{"negative window", policy.RateRule{Algorithm: "sliding-window", Count: 10, WindowSeconds: -60, Key: "subject"}, "INVALID_VALUE", "operations[0].rate.window_seconds"},
		{"window above the bound", policy.RateRule{Algorithm: "sliding-window", Count: 10, WindowSeconds: compile.MaxRateWindowSec + 1, Key: "subject"}, "INVALID_VALUE", "operations[0].rate.window_seconds"},
		{"token bucket", policy.RateRule{Algorithm: "token-bucket", Count: 10, WindowSeconds: 60, Key: "subject"}, "UNSUPPORTED_FEATURE", "operations[0].rate.algorithm"},
		{"fixed window", policy.RateRule{Algorithm: "fixed-window", Count: 10, WindowSeconds: 60, Key: "subject"}, "UNSUPPORTED_FEATURE", "operations[0].rate.algorithm"},
		{"missing algorithm", policy.RateRule{Algorithm: "", Count: 10, WindowSeconds: 60, Key: "subject"}, "UNSUPPORTED_FEATURE", "operations[0].rate.algorithm"},
		{"unsupported client_ip key", policy.RateRule{Algorithm: "sliding-window", Count: 10, WindowSeconds: 60, Key: "client_ip"}, "UNSUPPORTED_FEATURE", "operations[0].rate.key"},
		{"header key", policy.RateRule{Algorithm: "sliding-window", Count: 10, WindowSeconds: 60, Key: "X-Forwarded-For"}, "UNSUPPORTED_FEATURE", "operations[0].rate.key"},
		{"missing key", policy.RateRule{Algorithm: "sliding-window", Count: 10, WindowSeconds: 60, Key: ""}, "UNSUPPORTED_FEATURE", "operations[0].rate.key"},
	}
	for _, tc := range cases {
		p := threeAPIPolicy()
		p.Operations[0].Rate = &tc.rule
		g, err := compile.Compile(p, 1, time.Time{}, policy.Limits{})
		policyErr, ok := errors.AsType[*policy.PolicyError](err)
		if g != nil || !ok || policyErr.Code != tc.code || policyErr.Field != tc.field {
			t.Errorf("%s: generation %v error %v, want %s at %s", tc.name, g != nil, err, tc.code, tc.field)
		}
	}

	// A public operation has no verified subject to count per account.
	p = threeAPIPolicy()
	p.Operations[3].Rate = gatewaytest.Rate(10, 60)
	if err := compileErr(p); errorCode(err) != "INVALID_VALUE" || err.(*policy.PolicyError).Field != "operations[3].rate" {
		t.Errorf("rate rule on a public operation: %v", err)
	}

	// A valid rate rule next to an invalid body schema: nothing compiles.
	p = threeAPIPolicy()
	p.Operations[0].Rate = gatewaytest.Rate(10, 60)
	p.Operations[2].Body.Schema = []byte(`{"type":"object","additionalProperties":true,"$ref":"#"}`)
	if g, err := compile.Compile(p, 1, time.Time{}, policy.Limits{}); g != nil || errorCode(err) != "UNSUPPORTED_FEATURE" {
		t.Errorf("valid rate rule with an invalid schema: generation %v error %v", g != nil, err)
	}

	// Encodings the decoder must refuse rather than interpret.
	valid := `{"id":"x","api":"a","method":"GET","target":"/x","access":"allow","auth":"required","rate":%s}`
	documents := []struct {
		name, rate, code string
	}{
		{"count beyond int64", `{"algorithm":"sliding-window","count":1e30,"window_seconds":60,"key":"subject"}`, "SCHEMA_INVALID"},
		{"fractional count", `{"algorithm":"sliding-window","count":1.5,"window_seconds":60,"key":"subject"}`, "SCHEMA_INVALID"},
		{"count as text", `{"algorithm":"sliding-window","count":"10","window_seconds":60,"key":"subject"}`, "SCHEMA_INVALID"},
		{"repeated member", `{"algorithm":"sliding-window","count":10,"count":0,"window_seconds":60,"key":"subject"}`, "DUPLICATE_MEMBER"},
		{"unknown member", `{"algorithm":"sliding-window","count":10,"window_seconds":60,"key":"subject","burst":5}`, "UNKNOWN_FIELD"},
		{"missing window", `{"algorithm":"sliding-window","count":10,"key":"subject"}`, "INVALID_VALUE"},
	}
	for _, d := range documents {
		document := `{"schema_version":4,"profile":"core","upstreams":[{"id":"u","dial":"127.0.0.1:1"}],"apis":[{"id":"a","upstream":"u"}],` +
			`"operations":[` + fmt.Sprintf(valid, d.rate) + `]}`
		if got := errorCode(compileJSON(t, document)); got != d.code {
			t.Errorf("%s: %q, want %s", d.name, got, d.code)
		}
	}
	// A repeated rate member on one operation is the only way to declare two
	// rules for one target, and it is refused.
	twice := `{"schema_version":4,"profile":"core","upstreams":[{"id":"u","dial":"127.0.0.1:1"}],"apis":[{"id":"a","upstream":"u"}],` +
		`"operations":[{"id":"x","api":"a","method":"GET","target":"/x","access":"allow","auth":"required",` +
		`"rate":{"algorithm":"sliding-window","count":10,"window_seconds":60,"key":"subject"},` +
		`"rate":{"algorithm":"sliding-window","count":1000,"window_seconds":60,"key":"subject"}}]}`
	if got := errorCode(compileJSON(t, twice)); got != "DUPLICATE_MEMBER" {
		t.Errorf("two rules on one operation: %q", got)
	}
}
