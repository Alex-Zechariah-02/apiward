//go:build unix

// A named pipe in place of a key file is refused before it is opened, so a
// start or a reload never blocks on it.

package pipeline

import (
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
