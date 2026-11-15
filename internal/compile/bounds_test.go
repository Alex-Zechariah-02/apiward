// Exact bounds of policy compilation: request-body schema keywords, upstream
// URLs, access-check questions and targets, each limit's last accepted value
// and first refused one.

package compile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestSchemaKeywordBounds(t *testing.T) {
	properties := func(n int) string {
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf(`"p%d":{"type":"string"}`, i)
		}
		return `{"type":"object","additionalProperties":false,"properties":{` + strings.Join(names, ",") + `}}`
	}
	cases := []struct {
		name, schema string
		ok           bool
	}{
		{"equal string lengths", `{"type":"string","minLength":3,"maxLength":3}`, false},
		{"string lengths", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string","minLength":3,"maxLength":3}}}`, true},
		{"reversed string lengths", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string","minLength":4,"maxLength":3}}}`, false},
		{"negative length", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string","minLength":-1}}}`, false},
		{"zero length", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string","maxLength":0}}}`, true},
		{"longest length", fmt.Sprintf(`{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string","maxLength":%d}}}`, policy.MaxSchemaLength), true},
		{"length past the bound", fmt.Sprintf(`{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string","maxLength":%d}}}`, policy.MaxSchemaLength+1), false},
		{"array root", `{"type":"array","items":{"type":"string"}}`, true},
		{"string root", `{"type":"string"}`, false},
		{"equal item counts", `{"type":"array","items":{"type":"string"},"minItems":2,"maxItems":2}`, true},
		{"reversed item counts", `{"type":"array","items":{"type":"string"},"minItems":3,"maxItems":2}`, false},
		{"negative item count", `{"type":"array","items":{"type":"string"},"minItems":-1}`, false},
		{"zero items", `{"type":"array","items":{"type":"string"},"maxItems":0}`, true},
		{"most items", fmt.Sprintf(`{"type":"array","items":{"type":"string"},"maxItems":%d}`, policy.MaxJSONValues), true},
		{"items past the bound", fmt.Sprintf(`{"type":"array","items":{"type":"string"},"maxItems":%d}`, policy.MaxJSONValues+1), false},
		{"invalid item schema", `{"type":"array","items":{"type":"string","minLength":-1}}`, false},
		{"most properties", properties(policy.MaxSchemaProperties), true},
		{"properties past the bound", properties(policy.MaxSchemaProperties + 1), false},
		{"invalid property schema", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string","maxLength":-1}}}`, false},
		{"required declared", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string"}},"required":["a"]}`, true},
		{"required undeclared", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string"}},"required":["b"]}`, false},
		{"required repeated", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string"}},"required":["a","a"]}`, false},
		{"equal number bounds", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"number","minimum":2,"maximum":2}}}`, true},
		{"reversed number bounds", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"number","minimum":3,"maximum":2}}}`, false},
		{"integer bounds", `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"integer","minimum":1,"maximum":5}}}`, true},
	}
	for _, tc := range cases {
		_, _, err := CompileSchema([]byte(tc.schema), SchemaBody, "body")
		if (err == nil) != tc.ok {
			t.Errorf("%s: error %v, want accepted %v", tc.name, err, tc.ok)
		}
	}
	if _, _, err := CompileSchema([]byte(`{"type":"array","items":{"type":"string"}}`), SchemaHeaders, "headers"); err == nil {
		t.Error("an array header schema was accepted")
	}
}

func TestUpstreamURLBounds(t *testing.T) {
	label := func(n int) string { return strings.Repeat("a", n) }
	cases := []struct {
		raw string
		ok  bool
	}{
		{"https://" + label(63) + ".test", true},
		{"https://" + label(64) + ".test", false},
		{"https://" + label(63) + "." + label(63) + "." + label(63) + "." + label(61), true},
		{"https://" + label(63) + "." + label(63) + "." + label(63) + "." + label(62), false},
		{"https://-a.test", false},
		{"https://a-.test", false},
		{"https://z09.test", true},
		{"https://a.test:1", true},
		{"https://a.test:65535", true},
		{"https://a.test:0", false},
		{"https://a.test:65536", false},
		{"ftp://a.test", false},
		{"https://user@a.test", false},
	}
	for _, tc := range cases {
		if _, ok := parseUpstreamURL(tc.raw); ok != tc.ok {
			t.Errorf("%.40s: accepted %v, want %v", tc.raw, ok, tc.ok)
		}
	}
	for raw, host := range map[string]string{"https://a.test:443": "a.test", "https://a.test:8443": "a.test:8443"} {
		e, ok := parseUpstreamURL(raw)
		if !ok || hostHeader(e) != host {
			t.Errorf("%s: Host %q, want %q", raw, hostHeader(e), host)
		}
	}
}

func TestQuestionBounds(t *testing.T) {
	roles := func(n int) []string {
		list := make([]string, n)
		for i := range list {
			list[i] = fmt.Sprintf("R%d", i)
		}
		return list
	}
	headers := func(n int) map[string]string {
		set := map[string]string{}
		for i := range n {
			set[fmt.Sprintf("X-H%d", i)] = "v"
		}
		return set
	}
	long := "/" + strings.Repeat("p", policy.MaxTargetLength-1)
	cases := []struct {
		name, path, host string
		headers          map[string]string
		roles            []string
		field            string
	}{
		{"bounds reached", long, strings.Repeat("h", maxQuestionHost), headers(maxQuestionHeaders), roles(policy.MaxTokenRoles), ""},
		{"path too long", long + "p", "", nil, nil, "path"},
		{"too many roles", "/", "", nil, roles(policy.MaxTokenRoles + 1), "roles"},
		{"host too long", "/", strings.Repeat("h", maxQuestionHost+1), nil, nil, "host"},
		{"too many headers", "/", "", headers(maxQuestionHeaders + 1), nil, "headers"},
		{"longest header", "/", "", map[string]string{strings.Repeat("N", policy.MaxHeaderName): strings.Repeat("v", maxQuestionValue)}, nil, ""},
		{"header name too long", "/", "", map[string]string{strings.Repeat("N", policy.MaxHeaderName+1): "v"}, nil, "headers"},
		{"header value too long", "/", "", map[string]string{"X-A": strings.Repeat("v", maxQuestionValue+1)}, nil, "headers"},
		{"empty header name", "/", "", map[string]string{"": "v"}, nil, "headers"},
	}
	for _, tc := range cases {
		if _, field := NewQuestion("GET", tc.path, tc.host, tc.headers, tc.roles); field != tc.field {
			t.Errorf("%s: field %q, want %q", tc.name, field, tc.field)
		}
	}
}

func TestTargetBounds(t *testing.T) {
	for target, ok := range map[string]bool{
		"/" + strings.Repeat("t", policy.MaxTargetLength-1): true,
		"/" + strings.Repeat("t", policy.MaxTargetLength):   false,
		"/a*/b": false,
		"/!~":   true,
	} {
		if _, got := parseTarget(target); got != ok {
			t.Errorf("%.20s: accepted %v, want %v", target, got, ok)
		}
	}
}
