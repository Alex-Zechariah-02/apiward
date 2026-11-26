// Audit close loss records, writer failures and timeout.

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Events refused because the queue had no room for them are counted, and
// the count is written with the queued events when the writer continues:
// the stop reports no loss it did not see and hides none it did.
func TestAuditCloseRecordsLoss(t *testing.T) {
	a, release := heldAudit(t)
	room := RecordRoom(AuditQueueSize)
	for i := range room + 10 {
		a.Record(Event{Kind: "request.rejected", RequestID: strconv.Itoa(i)})
	}
	if a.lost.Load() != 10 || a.accepted.Load() != uint64(room) {
		t.Fatalf("lost %d, accepted %d", a.lost.Load(), a.accepted.Load())
	}
	release()
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	events := fileEvents(t, a.path)
	if len(events) != room+1 || lossCounted(events) != 10 || lossRecords(events) != 1 {
		t.Fatalf("%d records, loss %d in %d records", len(events), lossCounted(events), lossRecords(events))
	}
	// Records are numbered in file order: the loss record, written first,
	// is 1 and seq rises through the file (chain records, read past here,
	// take the numbers between batches). The refused events are counted by
	// the loss record, not by gaps.
	if loss := events[0]; loss.Kind != "audit.loss" || loss.Seq != 1 {
		t.Fatalf("first record %+v", loss)
	}
	previous := events[0].Seq
	for i, e := range events[1:] {
		if e.RequestID != strconv.Itoa(i) || e.Seq <= previous {
			t.Fatalf("record %d: request %q, seq %d after %d", i, e.RequestID, e.Seq, previous)
		}
		previous = e.Seq
	}
}

// A writer that can no longer write its file replaces it without a
// restart: the batch that failed is refused and its records are counted in
// a loss record in the new file, an audit.recovered record names
// the suspect file, the later batches (the admission among them) are saved,
// and the stop then reports nothing missing.
func TestAuditCloseReportsWriterFailure(t *testing.T) {
	a, release := heldAudit(t)
	room := RecordRoom(AuditQueueSize)
	for i := range room {
		a.Record(Event{Kind: "request.rejected", RequestID: strconv.Itoa(i)})
	}
	ack := make(chan error, 1)
	go func() { ack <- a.Commit(context.Background(), Event{Kind: "request.admitted"}) }()
	// accepted counts an event before its send completes, so only the queue's
	// length shows the admission has been queued behind the records.
	waitFor(t, time.Now().Add(5*time.Second), "the admission queued", func() bool { return len(a.queue) == room+1 })
	for range 3 {
		a.Record(Event{Kind: "request.rejected"})
	}
	// The file fails under the writer: the next write errors.
	a.file.Close()
	release()
	if err := <-ack; err != nil {
		t.Fatalf("the admission after the replacement: %v", err)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("close after the replaced file: %v", err)
	}
	if a.currentHealth() != healthWriting || a.Recoveries() != 1 {
		t.Fatalf("after the replacement: health %d, recoveries %d", a.currentHealth(), a.Recoveries())
	}
	var lost uint64
	recovered := false
	for _, e := range fileEvents(t, a.path) {
		lost += e.Lost * boolCount(e.Kind == "audit.loss")
		recovered = recovered || (e.Kind == "audit.recovered" && e.Reason == "sync_failed" && e.File != "")
	}
	// The failed batch, plus the 3 records refused while the queue was full.
	if !recovered || lost != auditBatchSize+3 {
		t.Fatalf("new file: recovered %v, lost %d, want %d", recovered, lost, auditBatchSize+3)
	}
}

func boolCount(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// A rotation that fails fails the log as a failed write does: the
// refused-event count its batch carried stays pending, and the stop reports
// it.
func TestAuditCloseKeepsLossAfterFailedRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	record := []byte(`{"kind":"earlier"}` + "\n")
	// The active file is full and its one rotated file is the last allowed.
	for _, name := range []string{path, path + ".1"} {
		if err := os.WriteFile(name, record, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := &AuditLog{
		boot:     "test",
		path:     path,
		maxBytes: int64(len(record)),
		maxFiles: 2,
		queue:    make(chan *auditEntry, AuditQueueSize),
		done:     make(chan struct{}),
	}
	if _, err := a.open(); err != nil {
		t.Fatal(err)
	}
	room := RecordRoom(AuditQueueSize)
	for i := range room + 3 {
		a.Record(Event{Kind: "request.rejected", RequestID: strconv.Itoa(i)})
	}
	go a.run()
	err := a.Close(context.Background())
	// The refused batch is counted with the refusals, as lost, and the log is
	// full rather than failed: it writes again once a file is moved away.
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("0 accepted events and the count of %d refused events not written", room+3)) {
		t.Fatalf("close after the failed rotation: %v", err)
	}
	if a.currentHealth() != healthFull {
		t.Fatalf("after the failed rotation: health %d; want healthFull", a.currentHealth())
	}
	if events := fileEvents(t, path); len(events) != 1 || events[0].Kind != "earlier" {
		t.Fatalf("records after the failed rotation: %+v", events)
	}
}

// An event refused after the close began is counted, and the writer, which
// ends only when the queue is closed and empty, writes that count as its last
// record: a stop that succeeds hides no refusal.
func TestAuditCloseWritesLossCountedWhileClosing(t *testing.T) {
	a, release := heldAudit(t)
	closed := make(chan error, 1)
	go func() { closed <- a.Close(context.Background()) }()
	waitFor(t, time.Now().Add(5*time.Second), "the close to begin", func() bool { return isClosing(a) })
	for range 3 {
		a.Record(Event{Kind: "request.rejected"})
	}
	release()
	if err := <-closed; err != nil {
		t.Fatalf("close: %v", err)
	}
	if events := fileEvents(t, a.path); len(events) != 1 || events[0].Kind != "audit.loss" || events[0].Lost != 3 {
		t.Fatalf("records %+v, want one loss record of 3", events)
	}
}

// A close whose bound ends while the writer is blocked returns at the bound
// with what is not confirmed written, and claims nothing more; it does not
// close the file under the writer. When the writer continues it writes
// everything and closes the file itself; a later close reports that.
func TestAuditCloseTimeout(t *testing.T) {
	a, release := heldAudit(t)
	for i := range 50 {
		a.Record(Event{Kind: "request.rejected", RequestID: strconv.Itoa(i)})
	}
	// The bound runs from the context's creation, so the clock starts first.
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := a.Close(ctx)
	if elapsed := time.Since(started); elapsed < 300*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("close returned after %s", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "not drained within the stop bound: 50 accepted events") {
		t.Fatalf("close at the bound: %v", err)
	}
	select {
	case <-a.done:
		t.Fatal("the held writer ended")
	default:
	}
	if a.file == nil || a.file.Sync() != nil {
		t.Fatal("the file was closed under the held writer")
	}

	release()
	<-a.done
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("close after the writer finished: %v", err)
	}
	if events := fileEvents(t, a.path); len(events) != 50 {
		t.Fatalf("%d records after the writer continued", len(events))
	}
}
