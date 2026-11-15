// Trust settings: clock skew, the smallest RSA key, key sizes reported,
// counters kept across a reload only for the same key, and the identity key
// size message.

package pipeline

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
)

// keyFile writes the public key of signer to a new file and returns its path.
func keyFile(t *testing.T, signer *issuertest.Issuer) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, signer.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTrustSettings(t *testing.T) {
	file := keyFile(t, issuer)
	trust := func(skew *string, bits *int) TrustConfig {
		c := testTrust(issuertest.Name, issuertest.Audience, file)
		c.ClockSkew, c.MinRSABits = skew, bits
		return c
	}
	text := func(s string) *string { return &s }
	number := func(n int) *int { return &n }
	for _, tc := range []struct {
		name   string
		config TrustConfig
	}{
		{"negative skew", trust(text("-1s"), nil)},
		{"skew above the maximum", trust(text("301s"), nil)},
		{"skew not a duration", trust(text("60"), nil)},
		{"key size not allowed", trust(nil, number(1024))},
		{"key size between the allowed", trust(nil, number(2560))},
		{"2,048-bit key under a 3,072-bit minimum", trust(nil, number(3072))},
	} {
		if _, err := LoadVerifier(tc.config); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	v, err := LoadVerifier(trust(nil, number(2048)))
	if err != nil || v.skew != DefaultClockSkew || len(v.Keys()) != 1 || v.Keys()[0].Bits != 2048 {
		t.Fatalf("defaults: %v, skew %v, keys %+v", err, v.skew, v.Keys())
	}
	if v, err := LoadVerifier(trust(text("5m"), nil)); err != nil || v.skew != MaxClockSkew {
		t.Fatalf("maximum skew: %v", err)
	}
}

// The leeway widens both validity times by exactly the configured skew.
func TestClockSkew(t *testing.T) {
	c := testTrust(issuertest.Name, issuertest.Audience, keyFile(t, issuer))
	skew := "60s"
	c.ClockSkew = &skew
	v, err := LoadVerifier(c)
	if err != nil {
		t.Fatal(err)
	}
	now := fixedNow.Unix()
	for _, tc := range []struct {
		name   string
		claims map[string]any
		reason string
	}{
		{"expired within the skew", claimsAt(map[string]any{"exp": now - 59}), ""},
		{"expired by the skew", claimsAt(map[string]any{"exp": now - 60}), "expired"},
		{"not yet valid within the skew", claimsAt(map[string]any{"nbf": now + 60}), ""},
		{"not yet valid past the skew", claimsAt(map[string]any{"nbf": now + 61}), "not_yet_valid"},
	} {
		if _, reason := v.verify(issuer.Token(t, tc.claims), fixedNow); reason != tc.reason {
			t.Errorf("%s: reason %q, want %q", tc.name, reason, tc.reason)
		}
	}
}

// A reload keeps a key's count only when its ID and material are unchanged.
func TestAdoptUses(t *testing.T) {
	first, other := keyFile(t, issuer), keyFile(t, issuertest.New(2048))
	load := func(file string) *Verifier {
		v, err := LoadVerifier(testTrust(issuertest.Name, issuertest.Audience, file))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	previous := load(first)
	if _, reason := previous.verify(issuer.Token(t, claimsAt(nil)), fixedNow); reason != "" {
		t.Fatal(reason)
	}
	same, replaced := load(first), load(other)
	same.AdoptUses(previous)
	replaced.AdoptUses(previous)
	if same.Use("test-a").Count() != 1 || replaced.Use("test-a").Count() != 0 {
		t.Fatalf("counts: same key %d, new key under the same ID %d", same.Use("test-a").Count(), replaced.Use("test-a").Count())
	}
}

// An identity key file over the size bound is reported as too large, not as
// a malformed key.
func TestSignerFileSize(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.pem")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), make([]byte, 64<<10)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("over-size key: %v", err)
	}
	if err := os.WriteFile(path, data[:len(data)-64<<10], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(path); err != nil {
		t.Fatalf("valid key: %v", err)
	}
}
