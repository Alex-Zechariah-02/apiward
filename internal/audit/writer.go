// The audit writer: batching, syncing, rotation and summaries.

package audit

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/fault"
)

// run is the writer. It writes the queued events in batches, in queue order,
// until the queue is closed and empty, which only close does; receiving from
// a closed channel yields every value still buffered first. Once per
// SummaryInterval it writes the ingress refusals counted. At the end it
// writes the last summary and the loss count still pending and closes the
// file.
func (a *AuditLog) run() {
	defer close(a.done)
	tick := time.NewTicker(SummaryInterval)
	defer tick.Stop()
	batch := make([]auditEntry, 0, auditBatchSize)
	for {
		select {
		case entry, open := <-a.queue:
			if !open {
				a.writeSummary()
				if a.lost.Load() > 0 {
					a.write(nil)
				}
				if a.file != nil {
					a.fileErr = a.file.Close()
				}
				return
			}
			batch = a.fill(append(batch[:0], entry))
			err := a.write(batch)
			switch {
			case err == nil:
				a.written.Add(uint64(len(batch)))
			case errors.Is(err, errStorageFull):
				// Refused, as at a full queue: no longer accepted, and those
				// nobody waits for are counted as lost.
				a.accepted.Add(-uint64(len(batch)))
			}
			for _, entry := range batch {
				if entry.done != nil {
					entry.done <- err
				}
			}
		case <-tick.C:
			a.writeSummary()
		}
	}
}

// fill adds the events already queued to batch, up to auditBatchSize.
func (a *AuditLog) fill(batch []auditEntry) []auditEntry {
	for len(batch) < auditBatchSize {
		select {
		case entry, open := <-a.queue:
			if !open {
				return batch
			}
			batch = append(batch, entry)
		default:
			return batch
		}
	}
	return batch
}

// writeSummary writes the ingress refusals counted since the last summary.
func (a *AuditLog) writeSummary() {
	if e, ok := a.takeSummary(); ok {
		a.write([]auditEntry{{event: a.stamp(e)}})
	}
}

// write appends batch, after the pending loss count, and syncs it. When a
// rotation is due and every file is in use, the batch is refused, its
// unacknowledged events are counted as lost and the log is full until a
// later rotation succeeds.
func (a *AuditLog) write(batch []auditEntry) error {
	if a.failed.Load() {
		return errAuditFailed
	}
	var buffer []byte
	lost := a.lost.Swap(0)
	if lost > 0 {
		buffer = appendEvent(buffer, a.stamp(Event{Kind: "audit.loss", Lost: lost}))
	}
	for _, entry := range batch {
		buffer = appendEvent(buffer, entry.event)
	}
	if a.size > 0 && a.size+int64(len(buffer)) > a.maxBytes {
		if err := a.makeRoom(); errors.Is(err, errFull) {
			a.lost.Add(lost + unacknowledged(batch))
			a.markFull(err)
			return errStorageFull
		} else if err != nil {
			a.lost.Add(lost)
			a.Fail(err)
			return errAuditFailed
		}
		rotated, err := a.rotate()
		if err != nil {
			// The count was not written, so it stays pending.
			a.lost.Add(lost)
			a.Fail(err)
			return errAuditFailed
		}
		marker := appendEvent(nil, a.stamp(Event{Kind: "audit.rotated", File: rotated}))
		buffer = append(marker, buffer...)
		a.full.Store(false)
	}
	if err := fault.WriteAudit(a.file, buffer); err != nil {
		a.lost.Add(lost)
		a.Fail(err)
		return errAuditFailed
	}
	a.size += int64(len(buffer))
	a.publishUsage()
	return nil
}

// publishUsage copies the writer's sizes and file count for other readers.
func (a *AuditLog) publishUsage() {
	a.activeBytes.Store(a.size)
	a.usedBytes.Store(a.size + a.rotatedBytes)
	a.files.Store(int64(a.rotated) + 1)
}

// unacknowledged counts the requests behind the events of batch nobody waits
// for: one each, or every refusal an ingress summary counts.
func unacknowledged(batch []auditEntry) uint64 {
	var n uint64
	for _, entry := range batch {
		if entry.done != nil {
			continue
		}
		counted := uint64(0)
		for _, count := range entry.event.Counts {
			counted += count
		}
		n += max(counted, 1)
	}
	return n
}

func appendEvent(buffer []byte, e Event) []byte {
	line, _ := json.Marshal(e)
	return append(append(buffer, line...), '\n')
}
