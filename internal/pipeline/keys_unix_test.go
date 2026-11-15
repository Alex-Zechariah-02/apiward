//go:build unix

// Key files on Unix: a named pipe in place of one is refused before it is
// opened, so a start or a reload never blocks on it, and a verification key
// another account could rewrite is refused.

package pipeline

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
)

func TestKeyFilePipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() {
		_, err := LoadVerifier(testTrust(issuertest.Name, issuertest.Audience, path))
		done <- err
	}()
	go func() {
		_, err := LoadSigner(path)
		done <- err
	}()
	for range 2 {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a named pipe was accepted as a key file")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("reading a named pipe as a key file blocked")
		}
	}
}

func TestKeyFileWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, issuer.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifier(testTrust(issuertest.Name, issuertest.Audience, path)); err != nil {
		t.Fatalf("private key file refused: %v", err)
	}
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifier(testTrust(issuertest.Name, issuertest.Audience, path)); err == nil {
		t.Fatal("a group-writable verification key was accepted")
	}
}
