// Key files of a test deployment, made at test time: the issuer's public key
// and the identity assertion key the gateway signs with by default.

package gatewaytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// IdentityFile is the identity key's name beside the database, where the
// gateway looks when the configuration names none.
const IdentityFile = "identity.pem"

// writeKeys writes e's issuer public key and a new identity key.
func writeKeys(t *testing.T, e *Env) {
	t.Helper()
	if err := os.WriteFile(e.PublicKey, Issuer.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	WriteIdentityKey(t, filepath.Join(filepath.Dir(e.Database), IdentityFile))
}

// WriteIdentityKey writes a new identity key at path, as apiward install
// creates it.
func WriteIdentityKey(tb testing.TB, path string) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		tb.Fatal(err)
	}
}
