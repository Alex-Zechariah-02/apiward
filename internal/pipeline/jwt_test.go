// JWT helpers, bearer extraction, signatures and headers.

package pipeline

import (
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
)

// These tests exercise token verification directly, at a fixed time, with
// genuine RS256 signatures from the test issuer. The same verifier runs in
// the gateway; the authentication integration tests cover that path.

// fixedNow is the validation time of every vector below.
var fixedNow = time.Unix(1_800_000_000, 0)

func testVerifier(t *testing.T) *Verifier {
	t.Helper()
	path := filepath.Join(t.TempDir(), "issuer.pem")
	if err := os.WriteFile(path, issuer.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := LoadVerifier(testTrust(issuertest.Name, issuertest.Audience, path))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// claimsAt is a valid claim set at fixedNow, with the given changes applied.
// A nil value removes the claim.
func claimsAt(changes map[string]any) map[string]any {
	claims := map[string]any{
		"sub": "staff-01",
		"iss": issuertest.Name,
		"aud": issuertest.Audience,
		"exp": fixedNow.Unix() + 600,
	}
	return issuertest.Changed(claims, changes)
}

// authenticate runs the whole authentication stage on Authorization fields.
func authenticate(v *Verifier, fields []string, now time.Time) (string, string) {
	token, reason := bearerToken(fields)
	if reason != "" {
		return "", reason
	}
	verified, reason := v.verify(token, now)
	return verified.subject, reason
}

func TestBearerCredentialExtraction(t *testing.T) {
	v := testVerifier(t)
	token := issuer.Token(t, claimsAt(nil))
	cases := []struct {
		name   string
		fields []string
		reason string
	}{
		{"valid", []string{"Bearer " + token}, ""},
		{"scheme in lower case", []string{"bearer " + token}, ""},
		{"scheme in upper case", []string{"BEARER " + token}, ""},
		{"no Authorization field", nil, "missing_credential"},
		{"empty field", []string{""}, "malformed_credential"},
		{"scheme only", []string{"Bearer"}, "malformed_credential"},
		{"scheme and space", []string{"Bearer "}, "malformed_credential"},
		{"two spaces", []string{"Bearer  " + token}, "malformed_credential"},
		{"trailing text", []string{"Bearer " + token + " extra"}, "malformed_credential"},
		{"other scheme", []string{"Basic " + token}, "malformed_credential"},
		{"token scheme", []string{"Token " + token}, "malformed_credential"},
		{"two fields", []string{"Bearer " + token, "Bearer " + token}, "malformed_credential"},
		{"two credentials in one field", []string{"Bearer " + token + ",Bearer " + token}, "malformed_credential"},
		{"padding characters", []string{"Bearer " + token + "=="}, "malformed_credential"},
		{"standard base64 characters", []string{"Bearer " + strings.Replace(token, "-", "+", 1) + "/"}, "malformed_credential"},
		{"two segments", []string{"Bearer " + token[:strings.LastIndex(token, ".")]}, "malformed_credential"},
		{"four segments", []string{"Bearer " + token + ".x"}, "malformed_credential"},
		{"empty signature", []string{"Bearer " + token[:strings.LastIndex(token, ".")+1]}, "malformed_credential"},
		{"oversize", []string{"Bearer " + token + strings.Repeat("A", MaxTokenBytes)}, "malformed_credential"},
		{"control character", []string{"Bearer " + token + "\x00"}, "malformed_credential"},
	}
	for _, tc := range cases {
		subject, reason := authenticate(v, tc.fields, fixedNow)
		if reason != tc.reason || (reason == "" && subject != "staff-01") {
			t.Errorf("%s: subject %q reason %q, want reason %q", tc.name, subject, reason, tc.reason)
		}
	}
}

func TestSignatureAndAlgorithm(t *testing.T) {
	v := testVerifier(t)
	payload := issuertest.ClaimsJSON(claimsAt(nil))
	valid := issuer.SignRaw(`{"alg":"RS256","typ":"JWT","kid":"test-a"}`, payload)
	segments := strings.Split(valid, ".")

	// Flip one bit of the signature, and swap in a payload signed for
	// nobody, keeping the original signature.
	signature, _ := base64.RawURLEncoding.DecodeString(segments[2])
	signature[10] ^= 0x01
	badSignature := segments[0] + "." + segments[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
	elevated := issuertest.ClaimsJSON(claimsAt(map[string]any{"sub": "mgr-01"}))
	swappedPayload := segments[0] + "." + issuertest.EncodeSegment(elevated) + "." + segments[2]

	other := issuertest.New(2048)

	cases := []struct {
		name   string
		token  string
		reason string
	}{
		{"genuine RS256 token from a standard signer", issuer.Token(t, claimsAt(nil)), ""},
		{"genuine RS256 token signed by hand", valid, ""},
		{"signature bit flipped", badSignature, "invalid_signature"},
		{"payload replaced after signing", swappedPayload, "invalid_signature"},
		{"untrusted key named by a trusted kid", other.SignRaw(`{"alg":"RS256","kid":"test-a"}`, payload), "invalid_signature"},
		{"alg none with a fake signature", issuertest.EncodeSegment(`{"alg":"none"}`) + "." + issuertest.EncodeSegment(payload) + ".AAAA", "unsupported_header"},
		{"alg None", issuertest.EncodeSegment(`{"alg":"None"}`) + "." + issuertest.EncodeSegment(payload) + ".AAAA", "unsupported_header"},
		{"HS256 keyed with the public key", issuertest.HMACToken(issuer.PublicPEM(), payload), "unsupported_header"},
		{"HS256 keyed with the key's DER", issuertest.HMACToken(publicDER(t), payload), "unsupported_header"},
		{"RS256 header over an HMAC signature", rs256HeaderOverHMAC(payload), "invalid_signature"},
		{"PS256", other.SignRaw(`{"alg":"PS256"}`, payload), "unsupported_header"},
		{"RS512", issuer.SignRaw(`{"alg":"RS512"}`, payload), "unsupported_header"},
		{"ES256", issuer.SignRaw(`{"alg":"ES256"}`, payload), "unsupported_header"},
		{"alg in lower case", issuer.SignRaw(`{"alg":"rs256"}`, payload), "unsupported_header"},
		{"alg missing", issuer.SignRaw(`{"typ":"JWT"}`, payload), "unsupported_header"},
		{"alg not a string", issuer.SignRaw(`{"alg":["RS256"]}`, payload), "unsupported_header"},
		{"header not JSON", issuer.SignRaw(`alg=RS256`, payload), "malformed_credential"},
		{"header an array", issuer.SignRaw(`["RS256"]`, payload), "malformed_credential"},
		{"header null", issuer.SignRaw(`null`, payload), "malformed_credential"},
		{"corrupt header encoding", "e" + valid, "malformed_credential"},
		{"corrupt signature encoding", valid + "A", "invalid_signature"},
	}
	for _, tc := range cases {
		subject, reason := authenticate(v, []string{"Bearer " + tc.token}, fixedNow)
		if reason != tc.reason || (reason == "" && subject != "staff-01") {
			t.Errorf("%s: subject %q reason %q, want reason %q", tc.name, subject, reason, tc.reason)
		}
	}
}

func publicDER(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&issuer.Key().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// rs256HeaderOverHMAC claims RS256 but carries an HMAC signature keyed with
// the public key: the verifier must use RSA and fail.
func rs256HeaderOverHMAC(payload string) string {
	forged := issuertest.HMACToken(issuer.PublicPEM(), payload)
	segments := strings.Split(forged, ".")
	return issuertest.EncodeSegment(`{"alg":"RS256","kid":"test-a"}`) + "." + segments[1] + "." + segments[2]
}

func TestHeaderMembers(t *testing.T) {
	v := testVerifier(t)
	payload := issuertest.ClaimsJSON(claimsAt(nil))

	// A key file that a kid could name: it must never be read.
	other := issuertest.New(2048)
	otherKey := filepath.Join(t.TempDir(), "other.pem")
	os.WriteFile(otherKey, other.PublicPEM(), 0o600)

	cases := []struct {
		name   string
		header string
		signer *issuertest.Issuer
		reason string
	}{
		{"typ JWT", `{"alg":"RS256","typ":"JWT","kid":"test-a"}`, issuer, ""},
		{"typ in lower case", `{"alg":"RS256","typ":"jwt","kid":"test-a"}`, issuer, ""},
		{"no typ", `{"alg":"RS256","kid":"test-a"}`, issuer, ""},
		{"unknown kid is refused", `{"alg":"RS256","kid":"key-1"}`, issuer, "unknown_kid"},
		{"kid naming a file", `{"alg":"RS256","kid":"` + filepath.ToSlash(otherKey) + `"}`, issuer, "unknown_kid"},
		{"kid naming a file, signed with that file's key", `{"alg":"RS256","kid":"` + filepath.ToSlash(otherKey) + `"}`, other, "unknown_kid"},
		{"kid traversal, signed with another key", `{"alg":"RS256","kid":"../../other.pem"}`, other, "unknown_kid"},
		{"kid not a string", `{"alg":"RS256","kid":7}`, issuer, "unsupported_header"},
		{"other typ", `{"alg":"RS256","kid":"test-a","typ":"at+jwt"}`, issuer, "unsupported_header"},
		{"typ not a string", `{"alg":"RS256","kid":"test-a","typ":null}`, issuer, "unsupported_header"},
		{"jku", `{"alg":"RS256","kid":"test-a","jku":"http://127.0.0.1:1/jwks.json"}`, issuer, "unsupported_header"},
		{"x5u", `{"alg":"RS256","kid":"test-a","x5u":"http://127.0.0.1:1/cert.pem"}`, issuer, "unsupported_header"},
		{"x5c", `{"alg":"RS256","kid":"test-a","x5c":["MIIB"]}`, issuer, "unsupported_header"},
		{"x5t#S256", `{"alg":"RS256","kid":"test-a","x5t#S256":"abc"}`, issuer, "unsupported_header"},
		{"embedded jwk", `{"alg":"RS256","kid":"test-a","jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}}`, issuer, "unsupported_header"},
		{"crit", `{"alg":"RS256","kid":"test-a","crit":["exp"],"exp":1}`, issuer, "unsupported_header"},
		{"unencoded payload", `{"alg":"RS256","kid":"test-a","b64":false,"crit":["b64"]}`, issuer, "unsupported_header"},
		{"nested token", `{"alg":"RS256","kid":"test-a","cty":"JWT"}`, issuer, "unsupported_header"},
		{"case variant of alg", `{"alg":"RS256","kid":"test-a","ALG":"none"}`, issuer, "unsupported_header"},
		{"repeated alg", `{"alg":"none","alg":"RS256"}`, issuer, "malformed_credential"},
		{"repeated alg, same value", `{"alg":"RS256","alg":"RS256"}`, issuer, "malformed_credential"},
	}
	for _, tc := range cases {
		subject, reason := v.verify(tc.signer.SignRaw(tc.header, payload), fixedNow)
		if reason != tc.reason || (reason == "" && subject.subject != "staff-01") {
			t.Errorf("%s: subject %q reason %q, want reason %q", tc.name, subject, reason, tc.reason)
		}
	}
}
