// The identity key install creates.

package operator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// Install writes an Ed25519 PKCS #8 key once and keeps a key already there.
func TestInstallIdentityKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.pem")
	if created, err := createIdentityKey(path); !created || err != nil {
		t.Fatalf("first install: %v %v", created, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("key file %q", data)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if _, ok := key.(ed25519.PrivateKey); err != nil || !ok {
		t.Fatalf("key %T: %v", key, err)
	}
	if created, err := createIdentityKey(path); created || err != nil {
		t.Fatalf("second install: %v %v", created, err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(again, data) {
		t.Fatal("an existing key was replaced")
	}
	// The key is written beside its place and linked in; nothing else stays.
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("files beside the key: %v %v", entries, err)
	}
}
