// Canonical request paths: encoded dots, slashes, backslashes and NUL are
// refused wherever they sit in the path.

package compile

import (
	"net/http"
	"net/url"
	"testing"
)

// An escape whose meaning could differ upstream is refused in either letter
// case, also after a harmless escape earlier in the path.
func TestCanonicalPathRefusesBannedEscapes(t *testing.T) {
	for _, tc := range []struct {
		escaped string
		ok      bool
	}{
		{"/a/b.c", true},
		{"/a%41", true},
		{"/a/b%2ec", false},
		{"/a/b%2Ec", false},
		{"/a/b%2fc", false},
		{"/a%41%2ec", false},
		{"/a%41%5cc", false},
		{"/a%41%00c", false},
	} {
		u, err := url.Parse(tc.escaped)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := CanonicalPath(&http.Request{URL: u}); ok != tc.ok {
			t.Errorf("%s: accepted %v, want %v", tc.escaped, ok, tc.ok)
		}
	}
}
