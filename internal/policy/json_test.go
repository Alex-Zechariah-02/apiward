// Bounded JSON decoding: lone UTF-16 surrogates are refused wherever their
// escape sits in a string.

package policy

import "testing"

// A lone surrogate is refused also right after another escape; a pair is
// accepted.
func TestLoneSurrogateAfterEscape(t *testing.T) {
	for _, tc := range []struct {
		document, code string
	}{
		{`{"a":"\n\ud800"}`, "invalid_encoding"},
		{`{"a":"\\\udc00"}`, "invalid_encoding"},
		{`{"a":"\n\ud800\udc00"}`, ""},
	} {
		if _, code := DecodeBounded([]byte(tc.document), MaxPolicyDepth, 100); code != tc.code {
			t.Errorf("%s: code %q, want %q", tc.document, code, tc.code)
		}
	}
}
