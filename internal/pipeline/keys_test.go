// Trust material validation.

package pipeline

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/testissuer"
)

// The gateway accepts only a single RSA public key of adequate size, and
// refuses to run with anything else, including the issuer's private key.
func TestTrustMaterialValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	smallDER, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	privateDER, _ := x509.MarshalPKCS8PrivateKey(issuer.Key())
	public := issuer.PublicPEM()

	valid := write("valid.pem", public)
	cases := []struct {
		name   string
		config TrustConfig
	}{
		{"missing file", testTrust(testissuer.Name, testissuer.Audience, filepath.Join(dir, "absent.pem"))},
		{"empty file", testTrust(testissuer.Name, testissuer.Audience, write("empty.pem", nil))},
		{"not PEM", testTrust(testissuer.Name, testissuer.Audience, write("garbage.pem", []byte("not a key")))},
		{"corrupted key", testTrust(testissuer.Name, testissuer.Audience, write("corrupt.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("corrupt")})))},
		{"PKCS#8 private key", testTrust(testissuer.Name, testissuer.Audience, write("private.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})))},
		{"PKCS#1 private key", testTrust(testissuer.Name, testissuer.Audience, write("rsa-private.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(issuer.Key())})))},
		{"PKCS#1 public key block", testTrust(testissuer.Name, testissuer.Audience, write("pkcs1.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&issuer.Key().PublicKey)})))},
		{"EC key", testTrust(testissuer.Name, testissuer.Audience, write("ec.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})))},
		{"1024-bit RSA key", testTrust(testissuer.Name, testissuer.Audience, write("small.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: smallDER})))},
		{"two keys in one PEM file", testTrust(testissuer.Name, testissuer.Audience, write("two.pem", append(append([]byte{}, public...), testissuer.New(2048).PublicPEM()...)))},
		{"key followed by its private key", testTrust(testissuer.Name, testissuer.Audience, write("pair.pem", append(append([]byte{}, public...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})...)))},
		{"text before the key", testTrust(testissuer.Name, testissuer.Audience, write("leading.pem", append([]byte("comment\n"), public...)))},
		{"text after the key", testTrust(testissuer.Name, testissuer.Audience, write("trailing.pem", append(append([]byte{}, public...), "comment\n"...)))},
		{"PEM headers", testTrust(testissuer.Name, testissuer.Audience, write("headers.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: publicDER(t)})))},
		{"oversize file", testTrust(testissuer.Name, testissuer.Audience, write("big.pem", append(append([]byte{}, public...), make([]byte, maxKeyFileBytes)...)))},
		{"no key file configured", testTrust(testissuer.Name, testissuer.Audience, "")},
		{"no issuer", testTrust("", testissuer.Audience, valid)},
		{"no audience", testTrust(testissuer.Name, "", valid)},
		{"issuer with a space", testTrust("issuer one", testissuer.Audience, valid)},
		{"overlong audience", testTrust(testissuer.Name, strings.Repeat("a", maxTrustValue+1), valid)},
	}
	for _, tc := range cases {
		if v, err := LoadVerifier(tc.config); err == nil {
			t.Errorf("%s: accepted (key %s)", tc.name, v.fingerprint)
		} else if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "MII") {
			t.Errorf("%s: error discloses key material: %v", tc.name, err)
		}
	}

	v, err := LoadVerifier(testTrust(testissuer.Name, testissuer.Audience, valid))
	if err != nil {
		t.Fatalf("valid trust configuration rejected: %v", err)
	}
	sum := sha256.Sum256(publicDER(t))
	if len(v.info) != 1 || v.info[0].Kid != "test-a" || v.info[0].Fingerprint != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("key metadata %+v, want kid and SHA-256 of the key's SubjectPublicKeyInfo", v.info)
	}
}
