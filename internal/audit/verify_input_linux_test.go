// Input files of audit verify that are not plain bounded log files, on
// Linux, where a FIFO and a sparse file are made without privilege.

//go:build linux

package audit

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Verify refuses a FIFO, and a plain file larger than any log file can be,
// without waiting for a writer or reading the file.
func TestVerifyRefusesIrregularAndHugeInput(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "audit-fifo.log")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	gzFifo := filepath.Join(dir, "audit-fifo.log.gz")
	if err := syscall.Mkfifo(gzFifo, 0o600); err != nil {
		t.Fatal(err)
	}
	huge := filepath.Join(dir, "audit-huge.log")
	if err := os.WriteFile(huge, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(huge, MaxAuditBytes+1); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, gzFifo, huge} {
		done := make(chan error, 1)
		go func() {
			_, err := VerifyChain([]string{path}, nil)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: verified", filepath.Base(path))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: verify still running after 5 s", filepath.Base(path))
		}
	}
}
