// Truthful and durable records: a withdrawn admission, a log that never
// opened, summary counts on a failed log, bounded records, the file mode,
// seq in file order and recovery once space returns.

package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// An admission whose wait ended before the writer took it is withdrawn and
// never written, so the refusal that follows is the request's only record.
func TestCommitWithdrawsOnTimeout(t *testing.T) {
	a, release := heldAudit(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Commit(ctx, Event{Kind: "request.admitted", RequestID: "late"}); !errors.Is(err, ErrTimedOut) {
		t.Fatalf("commit: %v", err)
	}
	release()
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, e := range fileEvents(t, a.path) {
		if e.RequestID == "late" {
			t.Fatalf("withdrawn admission written: %+v", e)
		}
	}
}

// A log that never opened reports that at Close instead of a clean drain.
func TestCloseReportsFailedOpen(t *testing.T) {
	a := OpenAudit(t.TempDir(), Settings{MaxBytes: DefaultAuditBytes, MaxFiles: DefaultAuditFiles})
	if err := a.Close(context.Background()); err == nil {
		t.Fatal("close of a log that never opened reported success")
	}
}

// An ingress summary the failed log cannot write keeps its counts as lost,
// which Close reports, instead of dropping them.
func TestSummaryCountsSurviveFailedLog(t *testing.T) {
	a, release := heldAudit(t)
	for range 3 {
		a.Summarise("not_origin_form", "192.0.2.1")
	}
	a.Fail(errors.New("test failure"))
	a.writeSummary()
	if a.lost.Load() != 3 {
		t.Fatalf("lost %d, want 3", a.lost.Load())
	}
	release()
	if err := a.Close(context.Background()); err == nil || !strings.Contains(err.Error(), "3 refused") {
		t.Fatalf("close: %v", err)
	}
}

// A record above MaxRecordBytes, which recovery relies on, is replaced by a
// bounded record that keeps its identity and decision.
func TestOversizedRecordReplaced(t *testing.T) {
	a, release := heldAudit(t)
	release()
	big := Event{Kind: "request.admitted", RequestID: "big", Decision: "admit", Subject: strings.Repeat("s", MaxRecordBytes)}
	if err := a.Commit(context.Background(), big); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if len(line) > MaxRecordBytes {
			t.Fatalf("record of %d bytes written", len(line))
		}
	}
	got := records(t, a.path)
	if len(got) != 1 || got[0].Kind != "audit.unwritable" || got[0].RequestID != "big" || got[0].Reason != "too_large" || got[0].Target != "request.admitted" {
		t.Fatalf("records %+v", got)
	}
}

// An existing audit file with a wider mode is narrowed to 0600 when opened.
func TestExistingFileModeTightened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows grants access by ACL, not mode bits")
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	a := OpenAudit(path, Settings{MaxBytes: DefaultAuditBytes, MaxFiles: DefaultAuditFiles})
	t.Cleanup(func() { a.Close(context.Background()) })
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
}

// Across rotations seq rises by exactly one in file order: the rotation
// marker at the head of each new file is numbered before the batch after it.
func TestSeqFollowsFileOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 700, MaxFiles: 64, Append: true})
	for range 30 {
		if err := a.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: "r"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotated, err := RotatedFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	var all []Event
	for _, file := range rotated {
		all = append(all, allRecords(t, filepath.Join(dir, file.Name))...)
	}
	all = append(all, allRecords(t, path)...)
	rotations := 0
	for i, e := range all {
		if e.Seq != uint64(i+1) {
			t.Fatalf("record %d (%s) has seq %d", i, e.Kind, e.Seq)
		}
		if e.Kind == "audit.rotated" {
			rotations++
		}
	}
	if rotations == 0 {
		t.Fatal("no rotation happened")
	}
}

// A log without space refuses admission at once, retries, and once a write
// succeeds again records how long it was off and admits again.
func TestNoSpaceRecovers(t *testing.T) {
	a, release := heldAudit(t)
	a.enterNoSpace(&os.PathError{Op: "write", Path: a.path, Err: syscall.ENOSPC})
	if err := a.Commit(context.Background(), Event{Kind: "request.admitted"}); err == nil {
		t.Fatal("admission accepted without space")
	}
	if !a.Failed() {
		t.Fatal("a log without space is not reported unavailable")
	}
	release()
	waitFor(t, time.Now().Add(5*time.Second), "space recovery", func() bool { return !a.Failed() })
	if err := a.Commit(context.Background(), Event{Kind: "request.admitted", RequestID: "after"}); err != nil {
		t.Fatalf("admission after recovery: %v", err)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := records(t, a.path)
	if len(got) != 2 || got[0].Kind != "audit.recovered" || got[0].Reason != "storage_space" || got[1].RequestID != "after" {
		t.Fatalf("records %+v", got)
	}
}

// Only a refused write is a space error; a failed sync never is, so it
// keeps failing the log until a restart.
func TestSpaceErrorClassifies(t *testing.T) {
	full := error(&os.PathError{Op: "write", Err: syscall.ENOSPC})
	if runtime.GOOS == "windows" {
		// ERROR_DISK_FULL
		full = &os.PathError{Op: "write", Err: syscall.Errno(112)}
	}
	if !spaceError(full) {
		t.Fatal("a full disk on write is not a space error")
	}
	if spaceError(syncError{full}) {
		t.Fatal("a failed sync is treated as recoverable")
	}
	if spaceError(errors.New("input/output error")) {
		t.Fatal("an I/O error is treated as recoverable")
	}
}
