// Durable audit queue: accepting, stamping and closing.

package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// auditEntry is one queued event. The queue holds pointers, so its ring
// keeps one word per place instead of a whole event.
type auditEntry struct {
	event Event
	done  chan error // nil for events that need no acknowledgement
	// state settles an acknowledged entry once: the writer takes it, or a
	// Commit whose wait ended withdraws it first, so it is never written.
	state atomic.Int32
}

// Acknowledged entry states.
const (
	entryQueued int32 = iota
	entryTaken
	entryWithdrawn
)

// ErrTimedOut is Commit's error when its wait ended before the record was
// synced. The record was withdrawn, or, if the writer had already taken it,
// is written; either way the caller records the refusal that supersedes it.
var ErrTimedOut = fmt.Errorf("%w: acknowledgement timed out", errAuditFailed)

// AuditLog writes events to a local file. Events that gate a decision wait
// until the batch containing them has been synced to disk; other events are
// queued without blocking and counted when they cannot be queued.
//
// An event is accepted when enqueue puts it in the queue. Every accepted event
// is written in order by the one writer, which ends only once close has
// closed the queue and every event in it has been written; so a close that
// returns nil means every accepted event, and the count of every refused one,
// is in the file and synced.
//
// On Linux, unless the settings ask to append, the active file is filled with
// zero bytes ahead of the writer and written in place; its content ends at
// End. The active file is rotated to "<path>.<n>" before it would exceed
// maxBytes.
// Once maxFiles files exist the log is full: it refuses records, and so
// protected admission, until an operator moves rotated files away, which it
// notices at its next rotation; or, when it may evict, it deletes the oldest
// rotated file after a synced record of what that file held.
type AuditLog struct {
	boot     string // distinguishes event identities across process starts
	path     string
	maxBytes int64
	maxFiles int
	file     *os.File // used only by the writer, which closes it as it ends
	size     int64    // logical size of the active file; used only by the writer
	// prefill zero-fills the active file ahead of the writer up to filled,
	// its physical size (see fill.go); used only by the writer.
	prefill bool
	filled  int64
	rotated int // rotated files present; used only by the writer
	// prepared delivers the description of preparing, the next file to
	// evict, made in the background (prepare.go); used only by the writer.
	prepared  chan describedFile
	preparing string
	// rotatedBytes is the rotated files' total size; used only by the writer.
	rotatedBytes int64
	// encoded is the last batch's memory, reused by the next batch; used
	// only by the writer.
	encoded []byte
	// seq numbers records in file order; used only by the writer.
	seq uint64
	// marker names the rotated file the next write must record first, set
	// when a rotation's marker is not yet written; used only by the writer.
	marker string
	evict  bool // delete the oldest rotated file when full
	// privacy is how client addresses are recorded; never changes.
	privacy Privacy
	// outcomeWindow bounds reconciliation after an unclean stop.
	outcomeWindow time.Duration
	// head is the chain head of the batches written since the start, and
	// signer signs its checkpoints (chain.go); used only by the writer.
	head   [sha256.Size]byte
	signer Signer
	// published copies head for readers outside the writer (ChainHead).
	published atomic.Pointer[[sha256.Size]byte]
	// window is how long a batch with siblings waits for more events
	// before its sync; 0 syncs each batch as soon as it is drained.
	window  time.Duration
	openErr error // why openAudit could not open the file; never changes
	queue   chan *auditEntry
	failed  atomic.Bool
	full    atomic.Bool // every file in use; cleared once a rotation succeeds
	// noSpace is set while the file system has no space for a write; the
	// writer clears it once a retried write and its sync succeed.
	noSpace atomic.Bool
	// spaceSince is when the log ran out of space; used only by the writer.
	spaceSince time.Time
	lost       atomic.Uint64 // events refused and not yet counted in the file
	// lossTotal and evictions count, since the start, the refused events
	// written in loss records and the files evicted, for the metrics.
	lossTotal atomic.Uint64
	evictions atomic.Uint64
	accepted  atomic.Uint64 // events queued
	// activeBytes and files copy size and rotated+1 for readers outside the
	// writer (the limits read); only the writer stores them.
	activeBytes atomic.Int64
	files       atomic.Int64
	usedBytes   atomic.Int64 // every file's bytes
	summary     ingressSummary
	written     atomic.Uint64 // queued events written and synced
	// mu orders queueing against closing: enqueue holds it shared while it
	// checks closing and queues, and close holds it exclusively while it sets
	// closing and closes the queue. Neither blocks while holding it.
	mu      sync.RWMutex
	closing bool
	done    chan struct{} // closed when the writer has ended
	fileErr error         // the result of closing the file; set by the writer before done
}

func (a *AuditLog) Fail(err error) {
	if a.failed.CompareAndSwap(false, true) {
		slog.Error("audit log failed; protected admission disabled", "error", err)
	}
}

// Commit records an event and waits for durable acknowledgement. A failed or
// closing log, a file system without space, or a full queue, refuses it at
// once. When ctx ends first it withdraws the event if the writer has not
// taken it, and returns ErrTimedOut.
func (a *AuditLog) Commit(ctx context.Context, e Event) error {
	if a.failed.Load() || a.noSpace.Load() {
		return errAuditFailed
	}
	entry := &auditEntry{event: e, done: make(chan error, 1)}
	if err := a.enqueue(entry); err != nil {
		return fmt.Errorf("%w: %v", errAuditFailed, err)
	}
	select {
	case err := <-entry.done:
		return err
	case <-ctx.Done():
		entry.state.CompareAndSwap(entryQueued, entryWithdrawn)
		return ErrTimedOut
	}
}

// Record queues an event without waiting. An event that cannot be queued,
// because the log has failed, its queue has no room for it (see RecordRoom)
// or it is closing, is counted; the writer writes the count with its next
// batch, or as it ends.
func (a *AuditLog) Record(e Event) {
	if a.failed.Load() || a.enqueue(&auditEntry{event: e}) != nil {
		a.lost.Add(1)
	}
}

// RecordRoom is how many queued events still leave room for an event nobody
// waits for: the last quarter of a queue of capacity events is kept for
// acknowledged ones (admissions, administrator intents). Refused requests
// need no sign-in, and a flood of their records must not refuse those.
func RecordRoom(capacity int) int { return capacity - capacity/4 }

// enqueue stamps and queues an entry, unless the log is closing or its queue
// has no room for it: an acknowledged entry (done set) may take any free
// place, any other only within RecordRoom. A refused event is counted in
// the next loss record; the writer numbers only written records, so seq
// rises by one in file order. Queueing never waits, so the read lock is held
// only briefly.
func (a *AuditLog) enqueue(entry *auditEntry) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closing {
		return errAuditClosed
	}
	// Counted before the writer can receive it, so written never exceeds
	// accepted.
	a.accepted.Add(1)
	entry.event = a.stamp(entry.event)
	if entry.done == nil && len(a.queue) >= RecordRoom(cap(a.queue)) {
		a.accepted.Add(^uint64(0))
		return errQueueFull
	}
	select {
	case a.queue <- entry:
		return nil
	default:
		a.accepted.Add(^uint64(0))
		return errQueueFull
	}
}

// stamp sets the schema and time of e and bounds its client-controlled
// strings; the writer numbers it (seal) as it writes it.
func (a *AuditLog) stamp(e Event) Event {
	e.Schema = EventSchema
	e.Time = time.Now().UTC()
	if e.ClientAddress != "" && a.privacy.Mode != "" {
		e.ClientAddress = a.privacy.address(e.ClientAddress)
	}
	for i := range e.Addresses {
		e.Addresses[i].Address = a.privacy.address(e.Addresses[i].Address)
	}
	// The method is cut silently: Truncated (path_truncated) is the path's.
	if len(e.Method) > MaxLoggedMethod {
		e.Method = e.Method[:MaxLoggedMethod]
	}
	if len(e.Path) > MaxLoggedPath {
		e.Path = e.Path[:MaxLoggedPath]
		e.Truncated = true
	}
	if len(e.ForwardedPath) > MaxLoggedPath {
		e.ForwardedPath = e.ForwardedPath[:MaxLoggedPath]
		e.Truncated = true
	}
	// A substring can retain the complete request target's backing storage.
	e.Method, e.Path, e.ForwardedPath = strings.Clone(e.Method), strings.Clone(e.Path), strings.Clone(e.ForwardedPath)
	return e
}

// seal numbers e as the next record in file order; only the writer calls it.
func (a *AuditLog) seal(e *Event) {
	a.seq++
	e.Seq = a.seq
	e.ID = a.boot + "-" + strconv.FormatUint(a.seq, 10)
}

// Close ends the log. From the moment it begins no event can be queued:
// Record counts it as lost and Commit refuses it. It then waits, until ctx is
// done, for the writer to write every event queued before, then the pending
// loss count, and to close the file. It returns nil only when all of that was
// written and synced; otherwise it reports what is not confirmed written. A
// writer blocked in the file system cannot be interrupted: when ctx ends
// first, the writer keeps the file and may still finish. Each later call
// reports the state it then finds.
func (a *AuditLog) Close(ctx context.Context) error {
	a.mu.Lock()
	if !a.closing {
		a.closing = true
		close(a.queue)
	}
	a.mu.Unlock()
	select {
	case <-a.done:
	case <-ctx.Done():
		select {
		case <-a.done:
		default:
			events, lost := a.Unconfirmed()
			return fmt.Errorf("audit log not drained within the stop bound: %d accepted events and the count of %d refused events not confirmed written", events, lost)
		}
	}
	if a.openErr != nil {
		return fmt.Errorf("audit log never opened: %w", a.openErr)
	}
	if events, lost := a.Unconfirmed(); events > 0 || lost > 0 {
		return fmt.Errorf("audit log incomplete: %d accepted events and the count of %d refused events not written", events, lost)
	}
	return a.fileErr
}

// Unconfirmed returns the number of accepted events not yet written and
// synced, and the count of refused events not yet in the file.
func (a *AuditLog) Unconfirmed() (events, lost uint64) {
	return a.accepted.Load() - a.written.Load(), a.lost.Load()
}
