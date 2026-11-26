// Forward bounds checked at their exact values: pinned roots per file, TLS
// profiles, and the size of a PEM file.

package forward

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A file of exactly maxPinned certificates loads; one more is refused.
func TestPinnedRootsAtBound(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var full, atBound []byte
	for i := range maxPinned + 1 {
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: fmt.Sprintf("root %d", i)},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		full = append(full, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		if i == maxPinned-1 {
			atBound = append([]byte{}, full...)
		}
	}
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		data []byte
		ok   bool
	}{{"at-bound.pem", atBound, true}, {"over-bound.pem", full, false}} {
		path := filepath.Join(dir, tc.name)
		if err := os.WriteFile(path, tc.data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRoots(path); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want loaded %v", tc.name, err, tc.ok)
		}
	}
}

// Exactly MaxProfiles TLS profiles load; one more is refused.
func TestProfilesAtBound(t *testing.T) {
	settings := make([]ProfileSettings, MaxProfiles+1)
	for i := range settings {
		settings[i].ID = fmt.Sprintf("p%d", i)
	}
	if _, err := LoadNetwork(false, settings[:MaxProfiles], 0); err != nil {
		t.Fatalf("%d profiles: %v", MaxProfiles, err)
	}
	if _, err := LoadNetwork(false, settings, 0); err == nil {
		t.Fatalf("%d profiles were loaded", len(settings))
	}
}

// A PEM file of exactly maxPEMBytes is read; one byte more is refused.
func TestPEMFileAtBound(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		size int
		ok   bool
	}{{maxPEMBytes, true}, {maxPEMBytes + 1, false}} {
		path := filepath.Join(dir, fmt.Sprintf("%d.pem", tc.size))
		if err := os.WriteFile(path, make([]byte, tc.size), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPEM(path, nil); (err == nil) != tc.ok {
			t.Errorf("%d bytes: %v, want read %v", tc.size, err, tc.ok)
		}
	}
}
