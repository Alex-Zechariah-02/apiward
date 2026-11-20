// Audit capacity: a full log writes again once files are moved away, an
// evicting log records a file before deleting it, and ingress refusals are
// summarised with exact counts.

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// commitN commits n events and returns how many were acknowledged.
func commitN(a *AuditLog, n int) int {
	acknowledged := 0
	for range n {
		if a.Commit(context.Background(), Event{Kind: "request.admitted"}) == nil {
			acknowledged++
		}
	}
	return acknowledged
}

// commitUntil commits one event at a time until done reports true. It fails
// the test on a refused commit, or when done does not hold within 1000
// commits.
func commitUntil(t *testing.T, a *AuditLog, done func() bool) {
	t.Helper()
	for i := 0; !done(); i++ {
		if i == 1000 {
			t.Fatal("the log did not reach the awaited state within 1000 commits")
		}
		if commitN(a, 1) != 1 {
			t.Fatal("a commit was refused")
		}
	}
}

func TestFullLogResumesWhenFilesMoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 4 << 10, MaxFiles: 2})
	t.Cleanup(func() {
		if err := a.Close(context.Background()); err != nil {
			t.Errorf("closing the log: %v", err)
		}
	})
	for i := 0; !a.Failed(); i++ {
		if i > 1000 {
			t.Fatal("the log never filled")
		}
		commitN(a, 1)
	}
	if a.failed.Load() || !a.full.Load() || commitN(a, 1) != 0 {
		t.Fatalf("full log: failed %v, full %v, or a commit was acknowledged", a.failed.Load(), a.full.Load())
	}
	moved := rotated(t, path)[0]
	if err := os.Rename(moved, filepath.Join(t.TempDir(), filepath.Base(moved))); err != nil {
		t.Fatal(err)
	}
	if commitN(a, 1) != 1 || a.Failed() {
		t.Fatal("after the rotated file was moved away the log still refused records")
	}
}

func TestEvictionRecordsBeforeDeleting(t *testing.T) {
	dir := t.TempDir()
	path, archive := filepath.Join(dir, "audit.log"), filepath.Join(dir, "archive")
	a := OpenAudit(path, Settings{MaxBytes: 4 << 10, MaxFiles: 64, WhenFull: FullEvict, Storage: Storage{Archive: archive}})
	var files []RotatedFile
	commitUntil(t, a, func() bool {
		files, _ = RotatedFiles(path, archive)
		return len(files) > 0 && files[0].Dir == archive
	})
	oldest, err := os.ReadFile(files[0].Path())
	if err != nil {
		t.Fatal(err)
	}
	header, err := ReadPacked(files[0].Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.archive.evict(files, 0, evictArchive); err != nil {
		t.Fatal(err)
	}
	if fileExists(files[0].Path()) {
		t.Fatal("the evicted file is still present")
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(oldest)
	// The archiver keeps writing, so the record may be in a rotated file.
	for _, e := range logRecords(t, path, archive) {
		if e.Kind == "audit.evicted" && e.Reason == evictArchive && e.File == files[0].Plain() {
			if e.File != files[0].Plain() || e.Bytes != int64(len(oldest)) || e.Digest != hex.EncodeToString(sum[:]) || !e.First.Equal(header.First) || !e.Last.Equal(header.Last) || e.Reason != evictArchive {
				t.Fatalf("eviction record %+v does not describe the deleted file", e)
			}
			return
		}
	}
	t.Fatal("the oldest file was deleted without an audit.evicted record")
}

func TestIngressSummaryCounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 2})
	for range 3 {
		a.Summarise("upgrade", "192.0.2.1")
	}
	a.Summarise("overloaded", "192.0.2.2")
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	events := records(t, path)
	if len(events) != 1 || events[0].Kind != "audit.ingress_summary" {
		t.Fatalf("records: %+v, want one ingress summary", events)
	}
	e := events[0]
	if e.Counts["upgrade"] != 3 || e.Counts["overloaded"] != 1 || len(e.Counts) != 2 {
		t.Fatalf("counts %v", e.Counts)
	}
	if len(e.Addresses) != 2 || e.Addresses[0] != (AddressCount{"192.0.2.1", 3}) || e.Addresses[1] != (AddressCount{"192.0.2.2", 1}) {
		t.Fatalf("addresses %v", e.Addresses)
	}
}

// records decodes every record of the file name but the chain records and
// a clean stop's last one, which their own tests check.
func records(t *testing.T, name string) []Event {
	t.Helper()
	var events []Event
	for _, e := range allRecords(t, name) {
		if e.Kind != closedKind && e.Kind != "audit.chain" {
			events = append(events, e)
		}
	}
	return events
}

// allRecords decodes every record of the file name, plain or compressed.
func allRecords(t *testing.T, name string) []Event {
	t.Helper()
	reader, err := OpenRecords(name)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	return events
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// rotated returns the paths of path's rotated files, oldest first.
func rotated(t *testing.T, path string) []string {
	t.Helper()
	files, err := RotatedFiles(path, "")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, file := range files {
		paths = append(paths, filepath.Join(filepath.Dir(path), file.Name))
	}
	return paths
}

// With a sync window, a lone record is synced at once, and every record is
// in the file when its commit is acknowledged. A lone record must return
// well before the window: half of it leaves room for a slow disk's sync.
func TestSyncWindow(t *testing.T) {
	const window = time.Second
	path := filepath.Join(t.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 2, Window: window})
	started := time.Now()
	if commitN(a, 1) != 1 || time.Since(started) > window/2 {
		t.Fatalf("a lone record waited %v, want no window", time.Since(started))
	}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			id := strconv.Itoa(i)
			if err := a.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: id}); err != nil {
				t.Error(err)
				return
			}
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Contains(data, []byte(`"request_id":"`+id+`"`)) {
				t.Errorf("record %s acknowledged before it was in the file", id)
			}
		})
	}
	wg.Wait()
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
