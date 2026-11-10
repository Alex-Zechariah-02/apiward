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
	"os"
	"path/filepath"
	"testing"
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

func TestFullLogResumesWhenFilesMoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 4 << 10, MaxFiles: 2})
	t.Cleanup(func() { a.Close(context.Background()) })
	for i := 0; !a.Failed(); i++ {
		if i > 1000 {
			t.Fatal("the log never filled")
		}
		commitN(a, 1)
	}
	if a.failed.Load() || !a.full.Load() || commitN(a, 1) != 0 {
		t.Fatalf("full log: failed %v, full %v, or a commit was acknowledged", a.failed.Load(), a.full.Load())
	}
	archive := filepath.Join(t.TempDir(), "audit.log.1")
	if err := os.Rename(path+".1", archive); err != nil {
		t.Fatal(err)
	}
	if commitN(a, 1) != 1 || a.Failed() {
		t.Fatal("after the rotated file was moved away the log still refused records")
	}
}

func TestEvictionRecordsBeforeDeleting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 4 << 10, MaxFiles: 2, WhenFull: FullEvict})
	for !fileExists(path + ".1") {
		commitN(a, 1)
	}
	oldest, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	for fileExists(path + ".1") {
		if commitN(a, 1) != 1 {
			t.Fatal("an evicting log refused a record")
		}
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(oldest)
	for _, name := range []string{path, path + ".2"} {
		for _, e := range records(t, name) {
			if e.Kind == "audit.evicted" {
				if e.File != "audit.log.1" || e.Bytes != int64(len(oldest)) || e.Digest != hex.EncodeToString(sum[:]) || e.First.IsZero() || e.Last.Before(e.First) {
					t.Fatalf("eviction record %+v does not describe the deleted file", e)
				}
				return
			}
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

// records decodes every record of the file name.
func records(t *testing.T, name string) []Event {
	t.Helper()
	data, err := os.ReadFile(name)
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
