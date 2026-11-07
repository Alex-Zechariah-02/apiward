// Request body decoding and JSON media types.

package pipeline

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// The body decoder accepts exactly one bounded, unambiguous JSON value.
func TestBodyDecoding(t *testing.T) {
	deep := func(n int) string { return strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n) }
	cases := []struct {
		name, body, reason string
	}{
		{"object", `{"a":1,"b":[true,null,"x"],"c":{"d":-1.5e3}}`, ""},
		{"surrounding whitespace", " \r\n\t{} \n", ""},
		{"escaped control character", `{"a":"\u0000\n"}`, ""},
		{"surrogate pair", `{"a":"😀"}`, ""},
		{"escaped backslash before u", `{"a":"\\ud800"}`, ""},
		{"empty", ``, "malformed_json"},
		{"whitespace only", "  ", "malformed_json"},
		{"truncated", `{"a":`, "malformed_json"},
		{"single quotes", `{'a':1}`, "malformed_json"},
		{"comment", `{"a":1}/*x*/`, "trailing_data"},
		{"raw control character", "{\"a\":\"\x01\"}", "malformed_json"},
		{"not a number", `{"a":NaN}`, "malformed_json"},
		{"byte order mark", "\xef\xbb\xbf{}", "malformed_json"},
		{"second value", `{}{}`, "trailing_data"},
		{"trailing text", `{} x`, "trailing_data"},
		{"trailing brace", `{}}`, "trailing_data"},
		{"repeated member", `{"a":1,"a":2}`, "duplicate_member"},
		{"repeated nested member", `{"a":{"b":1,"b":1}}`, "duplicate_member"},
		{"names differing in case", `{"a":1,"A":2}`, ""},
		{"invalid UTF-8", "{\"a\":\"\xff\"}", "invalid_encoding"},
		{"overlong UTF-8", "{\"a\":\"\xc0\xaf\"}", "invalid_encoding"},
		{"lone high surrogate", `{"a":"\ud800"}`, "invalid_encoding"},
		{"lone low surrogate", `{"a":"\udc00x"}`, "invalid_encoding"},
		{"reversed pair", `{"a":"\udc00\ud800"}`, "invalid_encoding"},
		{"nesting at the bound", deep(policy.MaxJSONDepth), ""},
		{"nesting above the bound", deep(policy.MaxJSONDepth + 1), "limit_exceeded"},
		{"values at the bound", "[" + strings.TrimSuffix(strings.Repeat("1,", policy.MaxJSONValues-1), ",") + "]", ""},
		{"values above the bound", "[" + strings.TrimSuffix(strings.Repeat("1,", policy.MaxJSONValues), ",") + "]", "limit_exceeded"},
		{"long number", `{"a":` + strings.Repeat("1", policy.MaxNumberLength+1) + `}`, "limit_exceeded"},
		{"large exponent", `{"a":1e999}`, ""},
		{"exponent above the bound", `{"a":1e1000}`, "limit_exceeded"},
		{"negative exponent above the bound", `{"a":1E-1000}`, "limit_exceeded"},
	}
	for _, tc := range cases {
		started := time.Now()
		_, reason := policy.DecodeJSON([]byte(tc.body))
		if reason != tc.reason {
			t.Errorf("%s: reason %q, want %q", tc.name, reason, tc.reason)
		}
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Errorf("%s: took %v", tc.name, elapsed)
		}
	}

	// The decoded value keeps numbers exact and every member.
	value, _ := policy.DecodeJSON([]byte(`{"n":12345678901234567890,"e":[],"o":{}}`))
	object := value.(map[string]any)
	if object["n"] != json.Number("12345678901234567890") || len(object["e"].([]any)) != 0 || len(object["o"].(map[string]any)) != 0 {
		t.Fatalf("decoded %#v", value)
	}
}

func TestMediaTypes(t *testing.T) {
	cases := []struct {
		fields []string
		ok     bool
	}{
		{[]string{"application/json"}, true},
		{[]string{"Application/JSON"}, true},
		{[]string{"application/json; charset=utf-8"}, true},
		{[]string{"application/json;charset=UTF-8"}, true},
		{[]string{"application/json; charset=\"utf-8\""}, true},
		{nil, false},
		{[]string{""}, false},
		{[]string{"application/json", "application/json"}, false},
		{[]string{"application/json; charset=latin1"}, false},
		{[]string{"application/json; charset=utf-16"}, false},
		{[]string{"application/json; boundary=x"}, false},
		// mime.ParseMediaType accepts a parameter repeated with the same
		// value, which is unambiguous, and refuses conflicting repeats.
		{[]string{"application/json; charset=utf-8; charset=utf-8"}, true},
		{[]string{"application/json; charset=utf-8; charset=latin1"}, false},
		{[]string{"application/json; charset=latin1; charset=utf-8"}, false},
		{[]string{"application/json;;"}, false},
		{[]string{"application/json, text/plain"}, false},
		{[]string{"text/json"}, false},
		{[]string{"text/plain"}, false},
		{[]string{"application/x-www-form-urlencoded"}, false},
		{[]string{"application/json-patch+json"}, false},
		{[]string{"application/problem+json"}, false},
		{[]string{"multipart/form-data; boundary=x"}, false},
	}
	for _, tc := range cases {
		if got := IsJSONMediaType(tc.fields); got != tc.ok {
			t.Errorf("%q: %v, want %v", tc.fields, got, tc.ok)
		}
	}
}
