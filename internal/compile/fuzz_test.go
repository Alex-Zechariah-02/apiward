// Fuzzing of the path canonicaliser, which decides the one reading of a
// request path that is both matched and forwarded.

package compile

import (
	"net/http"
	"net/url"
	stdpath "path"
	"strings"
	"testing"
)

// FuzzCanonicalPath checks that an accepted path is the single decoding of
// the request's path, already in the form path.Clean would give it, and made
// of printable characters without a backslash or a percent sign, so no
// upstream can read it differently.
func FuzzCanonicalPath(f *testing.F) {
	for _, seed := range []string{
		"/", "/a/b", "/a/b/", "/a//b", "/a/./b", "/a/../b", "/a/%2e%2e/b", "/a%2Fb", "/a%5cb",
		"/a%00", "/a%41", "/a b", "/a\\b", "/café", "/a;x=1", "/a?b=/../c", "*", "/..", "/.",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, target string) {
		u, err := url.ParseRequestURI(target)
		if err != nil {
			return
		}
		path, ok := CanonicalPath(&http.Request{URL: u})
		if !ok {
			if path != "" {
				t.Fatalf("refused %q but returned %q", target, path)
			}
			return
		}
		// The escaped form is forwarded as received: decoding it once must
		// give exactly the path that was matched.
		if decoded, err := url.PathUnescape(u.EscapedPath()); err != nil || decoded != path || path != u.Path {
			t.Fatalf("accepted %q as %q, but its forwarded form decodes to %q (%v)", target, path, decoded, err)
		}
		if cleaned := stdpath.Clean(path); path != "/" && cleaned != strings.TrimSuffix(path, "/") {
			t.Fatalf("accepted %q, which cleans to %q", path, cleaned)
		}
		for i := 0; i < len(path); i++ {
			if c := path[i]; c < 0x21 || c > 0x7e || c == '\\' || c == '%' {
				t.Fatalf("accepted %q with byte %#x", path, c)
			}
		}
	})
}
