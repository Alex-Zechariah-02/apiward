// Request body decoding, JSON media types and content codings.

package pipeline

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
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
		{"long number", `{"a":` + strings.Repeat("1", policy.MaxNumberLength+1) + `}`, "number_not_comparable"},
		{"large exponent", `{"a":1e999}`, ""},
		{"exponent above the bound", `{"a":1e1000}`, "number_not_comparable"},
		{"negative exponent above the bound", `{"a":1E-1000}`, "number_not_comparable"},
	}
	for _, tc := range cases {
		started := time.Now()
		_, reason := policy.DecodeJSON([]byte(tc.body))
		if reason != tc.reason {
			t.Errorf("%s: reason %q, want %q", tc.name, reason, tc.reason)
		}
		// A wide margin: a linear decoder takes microseconds here, while a
		// quadratic one on the bounded inputs takes seconds.
		if elapsed := time.Since(started); elapsed > 2*time.Second {
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

type errBody struct{ err error }

func (e errBody) Read([]byte) (int, error) { return 0, e.err }

// A declared Content-Length must not reserve memory before payload bytes
// arrive: a header-only request declaring 1 MiB allocates only a small
// initial buffer.
func TestBufferBodyGrowsWithBytes(t *testing.T) {
	const limit = 1 << 20
	req := httptest.NewRequest(http.MethodPost, "/a/item", errBody{err: io.ErrUnexpectedEOF})
	req.ContentLength = limit
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, refused := bufferBody(req, limit)
	runtime.ReadMemStats(&after)
	if refused == nil || refused.status != http.StatusBadRequest {
		t.Fatalf("truncated body: %+v, want 400", refused)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got >= 64<<10 {
		t.Fatalf("allocated %d bytes for 0 payload bytes with Content-Length %d; want < 64 KiB", got, limit)
	}
}

// A checked JSON body is read as the bytes received, so a body under a
// content coding is refused 415 rather than checked as something else; an
// operation without a body check is unchanged.
func TestEncodedJSONBodyRefused415(t *testing.T) {
	iss := issuertest.New(2048)
	v, err := LoadVerifier(testTrust(issuertest.Name, issuertest.Audience, keyFile(t, iss)))
	if err != nil {
		t.Fatal(err)
	}
	token := iss.Token(t, issuertest.Changed(issuertest.ValidClaims("cust-01"), map[string]any{"roles": []string{"customer"}}))
	cases := []struct {
		name, method, path string
		encoding           []string
		want               int
	}{
		{"gzip", http.MethodPost, "/items", []string{"gzip"}, http.StatusUnsupportedMediaType},
		{"identity", http.MethodPost, "/items", []string{"identity"}, http.StatusOK},
		{"gzip then identity", http.MethodPost, "/items", []string{"gzip, identity"}, http.StatusUnsupportedMediaType},
		{"two fields", http.MethodPost, "/items", []string{"identity", "gzip"}, http.StatusUnsupportedMediaType},
		{"no body check", http.MethodGet, "/a/x", []string{"gzip"}, http.StatusOK},
	}
	for _, tc := range cases {
		codes, events := serveRecorded(t, budgetPolicy(), v, 1, func() *http.Request {
			var body io.Reader
			if tc.method == http.MethodPost {
				body = strings.NewReader(`{"name":"a"}`)
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.Header.Set("Authorization", "Bearer "+token)
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			for _, value := range tc.encoding {
				req.Header.Add("Content-Encoding", value)
			}
			return req
		})
		if codes[0] != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, codes[0], tc.want)
		}
		if rejected := kindOf(events, "request.rejected"); tc.want == http.StatusUnsupportedMediaType && (len(rejected) != 1 || rejected[0]["reason"] != "content_encoding") {
			t.Errorf("%s: rejection records %v, want one with reason content_encoding", tc.name, rejected)
		}
	}
}
