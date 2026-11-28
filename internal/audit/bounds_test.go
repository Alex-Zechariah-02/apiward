// Audit log bounds at their exact values: rotation at the size bound, the
// first batch of an empty file, the live folder's bound with the active file
// counted, the free-space floor of a released reserve, and tombstones no
// reader needs.

package audit

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A batch whose records bring the active file to exactly its size bound
// stays in it; rotation waits for a batch that would pass the bound. The
// chain record written after each batch is not counted against the bound.
// Record lengths vary with their time and sequence, so each batch aims at
// the bound with the last record's length.
func TestRotationAtSizeBound(t *testing.T) {
	for range 20 {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		seed := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 64})
		if commitN(seed, 1) != 1 {
			t.Fatal("the first commit was refused")
		}
		if err := seed.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		record := lastRecordBytes(t, path)
		a := OpenAudit(path, Settings{MaxBytes: info.Size() + record, MaxFiles: 64})
		if commitN(a, 1) != 1 {
			a.Close(context.Background())
			t.Fatal("a commit was refused")
		}
		rotations := len(rotated(t, path))
		written := lastRecordBytes(t, path)
		if err := a.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if rotations == 0 && written == record {
			return
		}
	}
	t.Fatal("no batch ended exactly at the bound in 20 tries")
}

func TestOpenAuditOpenerErrorFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := openAuditWith(path, Settings{MaxBytes: 1 << 20, MaxFiles: 4}, withOpener(func(string, int, os.FileMode) (*os.File, error) {
		return nil, os.ErrPermission
	}))
	if !a.Failed() || a.OpenErr() == nil {
		t.Fatalf("failed=%v openErr=%v, want failed log", a.Failed(), a.OpenErr())
	}
}

// lastRecordBytes is the length, newline included, of the active file's
// last request record (skipping chain and close bookkeeping records).
func lastRecordBytes(t *testing.T, path string) int64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(Content(data)), "\n"), "\n")
	for _, line := range slices.Backward(lines) {
		if !strings.Contains(line, `"kind":"audit.chain"`) && !strings.Contains(line, `"kind":"audit.closed"`) {
			return int64(len(line) + 1)
		}
	}
	t.Fatal("no record in the active file")
	return 0
}

// A log whose bound is smaller than its first batch writes that batch to the
// empty active file instead of rotating the empty file away.
func TestFirstBatchOverBoundStaysInEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 1, MaxFiles: 64})
	commitN(a, 3)
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	files, err := RotatedFiles(path, "")
	if err != nil || len(files) == 0 {
		t.Fatalf("rotated files %v, %v", files, err)
	}
	for _, f := range files {
		if f.Bytes == 0 {
			t.Fatalf("rotated file %s is empty", f.Name)
		}
	}
}

// The active folder's bound counts the active file: rotated files that fit
// the bound alone are over it once the active file is added.
func TestLiveBoundCountsActiveFile(t *testing.T) {
	dir := t.TempDir()
	r := &archiver{live: dir, log: &AuditLog{maxBytes: 50, maxFiles: 2}}
	r.log.activeBytes.Store(30)
	files := []RotatedFile{{Name: "a", Dir: dir, Bytes: 40}, {Name: "b", Dir: dir, Bytes: 40}}
	if at := r.overLive(files, 0).at; at != 0 {
		t.Fatalf("80 rotated bytes beside a 30-byte active file under a 100-byte bound: picked %d, want 0", at)
	}
}

// While a reserve is released, a disk must also have twice the reserve free;
// a fully held reserve sets no such floor.
func TestPressureFloorWhileReserveReleased(t *testing.T) {
	dir := t.TempDir()
	r := &archiver{live: dir, dir: t.TempDir(), reserve: 1 << 50, log: &AuditLog{}}
	files := []RotatedFile{{Name: "a", Dir: dir, Bytes: 1}}
	r.held.Store(r.reserve)
	if at := r.underPressure(files, 0).at; at != -1 {
		t.Fatalf("held reserve: picked %d, want none", at)
	}
	r.held.Store(r.reserve - 1)
	if at := r.underPressure(files, 0).at; at != 0 {
		t.Fatalf("released reserve below twice its size free: picked %d, want 0", at)
	}
}

// With no rotated file present, every tombstone is one no reader needs.
func TestSweepRemovesUnneededTombstones(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 4, Storage: Storage{Archive: filepath.Join(dir, "archive")}})
	t.Cleanup(func() { a.Close(context.Background()) })
	if err := tombstone(dir, "audit-gone.log"); err != nil {
		t.Fatal(err)
	}
	a.archive.sweep(nil)
	if names, err := Tombstones(path); err != nil || len(names) != 0 {
		t.Fatalf("tombstones after a sweep: %v (%v)", names, err)
	}
}
