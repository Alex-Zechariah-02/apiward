// Security log search over written files: paging, cursors and filters.

package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// writeAuditFile writes request records numbered from..to (oldest first) with
// an administrator record between them, as the writer would.
func writeAuditFile(t *testing.T, path string, from, to int, tail string) {
	t.Helper()
	var text strings.Builder
	base := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	for n := from; n <= to; n++ {
		kind, decision := "request.forwarded", "forwarded"
		if n%2 == 0 {
			kind, decision = "request.rejected", "reject"
		}
		line, _ := json.Marshal(audit.Event{
			ID: fmt.Sprintf("e-%d", n), Time: base.Add(time.Duration(n) * time.Second), Kind: kind, RequestID: fmt.Sprintf("%032x", n),
			Stage: "FORWARD", Decision: decision, Status: 200, Method: "GET", Path: fmt.Sprintf("/a/%d", n), Operation: "read-a",
			Subject: fmt.Sprintf("user-%d", n%3), Roles: []string{"READER"},
		})
		text.Write(line)
		text.WriteString("\n" + `{"event_id":"admin-` + fmt.Sprint(n) + `","kind":"admin.read","path":"/admin/status"}` + "\n")
	}
	text.WriteString(tail)
	if err := os.WriteFile(path, []byte(text.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func refsOf(items []RequestView) []string {
	refs := []string{}
	for _, item := range items {
		refs = append(refs, strings.TrimLeft(item.RequestID, "0"))
	}
	return refs
}

func TestSecurityLogSearch(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	writeAuditFile(t, active+".2", 1, 4, "")
	writeAuditFile(t, active+".3", 5, 8, "")
	// The active file ends with a record still being written and the zero
	// tail of a zero-filled file (one 1 MiB fill step).
	writeAuditFile(t, active, 9, 12, `{"event_id":"e-13","kind":"request.forw`+strings.Repeat("\x00", 1<<20))
	files, missing, err := LogFiles(active)
	if err != nil || !slices.Equal(files, []string{"audit.log", "audit.log.3", "audit.log.2"}) || !slices.Equal(missing, []string{"audit.log.1"}) {
		t.Fatalf("files %v, missing %v (%v)", files, missing, err)
	}

	// Newest first across files; administrator records and the incomplete
	// line are not request results.
	all, err := Search(dir, files, nil, Query{}, 100, PageScan)
	want := []string{"c", "b", "a", "9", "8", "7", "6", "5", "4", "3", "2", "1"}
	if err != nil || !slices.Equal(refsOf(all.Items), want) || all.Next != nil || all.Unreadable != 0 {
		t.Fatalf("all: %v next %v unreadable %d (%v)", refsOf(all.Items), all.Next, all.Unreadable, err)
	}
	if all.Items[0].Decision != "refused" || all.Items[1].Decision != "allowed" || all.Items[1].Stage != "forward" {
		t.Errorf("projection: %+v", all.Items[:2])
	}

	// Pages of three, and a tiny scan budget, both reach every record once.
	for _, tc := range []struct {
		limit int
		scan  int64
	}{{3, PageScan}, {100, 400}} {
		got := []string{}
		var cursor *Cursor
		for page := 0; page < 50; page++ {
			result, err := Search(dir, files, cursor, Query{}, tc.limit, tc.scan)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, refsOf(result.Items)...)
			if result.Next == nil {
				break
			}
			cursor = DecodeCursor(EncodeCursor(*result.Next))
		}
		if !slices.Equal(got, want) {
			t.Errorf("limit %d scan %d: %v", tc.limit, tc.scan, got)
		}
	}

	// Filters.
	for _, tc := range []struct {
		query Query
		want  []string
	}{
		{Query{ref: fmt.Sprintf("%032x", 7)}, []string{"7"}},
		{Query{subject: "user-1"}, []string{"a", "7", "4", "1"}},
		{Query{decision: "refused"}, []string{"c", "a", "8", "6", "4", "2"}},
		{Query{from: time.Date(2026, 11, 2, 9, 0, 5, 0, time.UTC), to: time.Date(2026, 11, 2, 9, 0, 8, 0, time.UTC)}, []string{"7", "6", "5"}},
		{Query{operation: "other"}, []string{}},
	} {
		result, err := Search(dir, files, nil, tc.query, 100, PageScan)
		if err != nil || !slices.Equal(refsOf(result.Items), tc.want) {
			t.Errorf("%+v: %v (%v)", tc.query, refsOf(result.Items), err)
		}
	}

	// A page that stopped in the active file resumes after a rotation renamed
	// it: the cursor finds the file by its first record.
	first, err := Search(dir, files, nil, Query{}, 2, PageScan)
	if err != nil || first.Next == nil || first.Next.File != "audit.log" {
		t.Fatalf("first page: %+v (%v)", first.Next, err)
	}
	if err := os.Rename(active, active+".4"); err != nil {
		t.Fatal(err)
	}
	writeAuditFile(t, active, 20, 21, "")
	files, _, _ = LogFiles(active)
	rest, err := Search(dir, files, first.Next, Query{}, 100, PageScan)
	if err != nil || !slices.Equal(refsOf(rest.Items), want[2:]) {
		t.Errorf("after rotation: %v (%v)", refsOf(rest.Items), err)
	}
	// A file moved away to archive ends that cursor clearly.
	os.Remove(active + ".4")
	files, _, _ = LogFiles(active)
	if _, err := Search(dir, files, first.Next, Query{}, 100, PageScan); err != ErrCursorGone {
		t.Errorf("archived cursor: %v", err)
	}

	// A damaged request record is counted, not hidden.
	os.WriteFile(active, []byte(`{"event_id":"x","kind":"request.rejected","time":"not a time"}`+"\n"), 0o600)
	if result, _ := Search(dir, []string{"audit.log"}, nil, Query{}, 100, PageScan); result.Unreadable != 1 || len(result.Items) != 0 {
		t.Errorf("damaged record: %+v", result)
	}

	for _, text := range []string{"", "!!", EncodeCursor(Cursor{File: "../audit.log"}), EncodeCursor(Cursor{File: "audit.log", Offset: -2})} {
		if DecodeCursor(text) != nil {
			t.Errorf("cursor %q accepted", text)
		}
	}
}

// A read of the security log never stops the writer: while a scan holds a
// file open, the writer can still rename the active file at a rotation and
// delete the oldest rotated file at an eviction. Either failing would fail
// the log and stop protected admission.
func TestScanAllowsRotation(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	writeAuditFile(t, active, 1, 4, "")
	budget := int64(1 << 20)
	var renamed error
	if _, _, err := scanLinesBackward(active, -1, &budget, func([]byte, int64) bool {
		renamed = os.Rename(active, active+".1")
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if renamed != nil {
		t.Fatalf("rotation rename during a scan: %v", renamed)
	}
	var removed error
	if _, _, err := scanLinesBackward(active+".1", -1, &budget, func([]byte, int64) bool {
		removed = os.Remove(active + ".1")
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if removed != nil {
		t.Fatalf("eviction delete during a scan: %v", removed)
	}
	if _, err := os.Stat(active + ".1"); !os.IsNotExist(err) {
		t.Fatalf("evicted file still listed: %v", err)
	}
}
