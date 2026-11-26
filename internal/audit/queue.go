// Durable audit queue: accepting, stamping and closing.

package audit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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

// Commit records an event and waits for durable acknowledgement. A failed or
// closing log, a file system without space, or a full queue, refuses it at
// once. When ctx ends first it withdraws the event if the writer has not
// taken it, and returns ErrTimedOut.
func (a *AuditLog) Commit(ctx context.Context, e Event) error {
	if h := a.currentHealth(); h == healthFailed || h == healthNoSpace || h == healthDown {
		return errAuditFailed
	}
	entry := &auditEntry{event: e, done: make(chan error, 1)}
	if err := a.enqueue(entry); err != nil {
		return fmt.Errorf("%w: %v", errAuditFailed, err)
	}
	start := time.Now()
	select {
	case err := <-entry.done:
		a.saves.observe(time.Since(start))
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
	if a.currentHealth() == healthFailed || a.enqueue(&auditEntry{event: e}) != nil {
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
	// The archiver's records need the queue, so it stops first.
	a.archive.halt(ctx)
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
