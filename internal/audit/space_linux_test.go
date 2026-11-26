// Linux full-disk eviction test using /dev/full through the file opener option.

//go:build linux

package audit

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// When an eviction record begins while healthy and its write meets ENOSPC,
// writeEviction releases the eviction reserve before retrying.
func TestEvictionWriteMeetsFullDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	evictReserve := evictReserveName(path)
	if err := os.WriteFile(evictReserve, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	var opens atomic.Int32
	opener := func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if opens.Add(1) == 2 {
			return os.OpenFile("/dev/full", os.O_WRONLY, 0)
		}
		return os.OpenFile(name, flag, perm)
	}
	a := openAuditWith(path, Settings{MaxBytes: 1, MaxFiles: 8, WhenFull: FullEvict, Storage: Storage{Reserve: 64 << 10}}, withOpener(opener))
	t.Cleanup(func() { a.Close(context.Background()) })
	if err := a.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: "seed"}); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	// The next write rotates and opens /dev/full, so writeEviction hits ENOSPC
	// from healthWriting and must release the eviction reserve.
	if err := a.commitEviction(context.Background(), Event{Kind: "audit.evicted", File: "audit-1.log", Reason: evictPressure}); err == nil {
		t.Fatal("eviction write to /dev/full succeeded")
	}
	if fileExists(evictReserve) {
		t.Fatal("eviction reserve was not released after writeBatch hit ENOSPC")
	}
}
