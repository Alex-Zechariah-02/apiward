// Fuzzing of token verification, the first reader of every caller's
// credential.

package pipeline

import (
	"strings"
	"testing"
)

// FuzzVerify checks that verification never panics and accepts a token only
// if its signed part is exactly that of a token the trusted issuer signed:
// the fuzzer has no key, so any other accepted input is a forgery.
func FuzzVerify(f *testing.F) {
	v := testVerifier(f)
	valid := issuer.Token(f, claimsAt(nil))
	signed := valid[:strings.LastIndex(valid, ".")]
	header, payload, _ := strings.Cut(signed, ".")
	for _, seed := range []string{
		valid, signed + ".", signed, header + "." + payload + "." + payload, header + ".e30." + valid[len(signed)+1:],
		rs256HeaderOverHMAC(payload), "a.b.c", "..", "", "eyJhbGciOiJub25lIn0.e30.",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		verified, reason := v.verify(token, fixedNow)
		if reason != "" {
			if verified.subject != "" {
				t.Fatalf("refused with %q but returned subject %q", reason, verified.subject)
			}
			return
		}
		if end := strings.LastIndex(token, "."); end < 0 || token[:end] != signed {
			t.Fatalf("accepted a token the issuer did not sign: %q", token)
		}
	})
}
