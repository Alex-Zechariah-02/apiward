// Input files of audit verify's key set that are not plain bounded files, on
// Linux, where a FIFO is made without privilege.

//go:build linux

package main

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The key set read refuses a FIFO instead of waiting for a writer.
func TestKeySetRefusesFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "keys.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readKeySet(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was read as a key set")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the key set read still waiting on a FIFO after 5 s")
	}
}
