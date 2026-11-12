// Durable audit queue: accepting, stamping and closing.

package audit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type auditEntry struct {
	event Event
	done  chan error // nil for events that need no acknowledgement
}

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
	next    int // suffix of the next rotated file; used only by the writer
	// rotatedBytes is the rotated files' total size; used only by the writer.
	rotatedBytes int64
	evict        bool // delete the oldest rotated file when full
	// window is how long a batch with siblings waits for more events
	// before its sync; 0 syncs each batch as soon as it is drained.
	window   time.Duration
	openErr  error // why openAudit could not open the file; never changes
	queue    chan auditEntry
	failed   atomic.Bool
	full     atomic.Bool   // every file in use; cleared once a rotation succeeds
	lost     atomic.Uint64 // events refused and not yet counted in the file
	seq      atomic.Uint64
	accepted atomic.Uint64 // events queued
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
		fmt.Fprintf(os.Stderr, "apiward: audit log failed; protected admission disabled: %v\n", err)
	}
}

// Commit records an event and waits for durable acknowledgement. A failed or
// closing log, or a full queue, refuses it at once.
func (a *AuditLog) Commit(ctx context.Context, e Event) error {
	if a.failed.Load() {
		return errAuditFailed
	}
	done := make(chan error, 1)
	if err := a.enqueue(e, done); err != nil {
		return fmt.Errorf("%w: %v", errAuditFailed, err)
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("%w: acknowledgement timed out", errAuditFailed)
	}
}

// Record queues an event without waiting. An event that cannot be queued,
// because the log has failed, its queue has no room for it (see RecordRoom)
// or it is closing, is counted; the writer writes the count with its next
// batch, or as it ends.
func (a *AuditLog) Record(e Event) {
	if a.failed.Load() || a.enqueue(e, nil) != nil {
		a.lost.Add(1)
	}
}

// RecordRoom is how many queued events still leave room for an event nobody
// waits for: the last quarter of a queue of capacity events is kept for
// acknowledged ones (admissions, administrator intents). Refused requests
// need no sign-in, and a flood of their records must not refuse those.
func RecordRoom(capacity int) int { return capacity - capacity/4 }

// enqueue stamps and queues an event, unless the log is closing or its queue
// has no room for it: an acknowledged event (done set) may take any free
// place, any other only within RecordRoom. A refused event keeps its
// sequence number, so the gap stays visible. Queueing never waits, so the
// read lock is held only briefly.
func (a *AuditLog) enqueue(e Event, done chan error) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closing {
		return errAuditClosed
	}
	// Counted before the writer can receive it, so written never exceeds
	// accepted.
	a.accepted.Add(1)
	entry := auditEntry{event: a.stamp(e), done: done}
	if done == nil && len(a.queue) >= RecordRoom(cap(a.queue)) {
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

func (a *AuditLog) stamp(e Event) Event {
	e.Schema = EventSchema
	e.Time = time.Now().UTC()
	e.Seq = a.seq.Add(1)
	e.ID = fmt.Sprintf("%s-%d", a.boot, e.Seq)
	if len(e.Path) > MaxLoggedPath {
		e.Path = e.Path[:MaxLoggedPath]
		e.Truncated = true
	}
	if len(e.ForwardedPath) > MaxLoggedPath {
		e.ForwardedPath = e.ForwardedPath[:MaxLoggedPath]
		e.Truncated = true
	}
	// A substring can retain the complete request target's backing storage.
	e.Path, e.ForwardedPath = strings.Clone(e.Path), strings.Clone(e.ForwardedPath)
	return e
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
