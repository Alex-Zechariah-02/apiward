// The signing key's type fixes the assertion's algorithm: an Ed25519 key
// signs EdDSA, a P-256 key ES256, and the published key set says so.

package pipeline

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignerFollowsKeyType(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key       any
		algorithm string
		keyType   string
	}{{edKey, "EdDSA", "OKP"}, {ecKey, "ES256", "EC"}} {
		der, err := x509.MarshalPKCS8PrivateKey(tc.key)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "identity.pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadSigner(path)
		if err != nil {
			t.Fatal(err)
		}
		token, err := s.sign(claims{Audience: "orders", Method: "GET", Path: "/orders"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(token, ".")
		header, _ := base64.RawURLEncoding.DecodeString(parts[0])
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		var fields map[string]string
		if json.Unmarshal(header, &fields) != nil || fields["alg"] != tc.algorithm || fields["kid"] != s.KeyID() || len(signature) != 64 {
			t.Fatalf("%s: header %s, signature %d bytes", tc.algorithm, header, len(signature))
		}
		if tc.algorithm == "EdDSA" && !ed25519.Verify(edKey.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), signature) {
			t.Fatal("the EdDSA assertion does not verify")
		}
		var set struct {
			Keys []map[string]string `json:"keys"`
		}
		if json.Unmarshal(s.JWKS(), &set) != nil || len(set.Keys) != 1 || set.Keys[0]["kty"] != tc.keyType || set.Keys[0]["alg"] != tc.algorithm {
			t.Fatalf("%s: key set %s", tc.algorithm, s.JWKS())
		}
	}
}
