// The audit writer: batching, numbering, syncing, rotation and summaries.

package audit

import (
	"errors"
	"time"
)

// run is the writer. It writes the queued events in batches, in queue order,
// until the queue is closed and empty, which only close does; receiving from
// a closed channel yields every value still buffered first. Once per
// SummaryInterval it writes the ingress refusals counted, and while the file
// system has no space, or the active file is being replaced, it retries
// once per spaceRetry. At the end it writes
// the last summary and the loss count still pending and closes the file.
func (a *AuditLog) run() {
	defer close(a.done)
	tick := time.NewTicker(SummaryInterval)
	defer tick.Stop()
	checkpoints := time.NewTicker(CheckpointInterval)
	defer checkpoints.Stop()
	retry := time.NewTicker(spaceRetry)
	defer retry.Stop()
	window := time.NewTimer(0)
	defer window.Stop()
	batch := make([]*auditEntry, 0, auditBatchSize)
	for {
		select {
		case entry := <-a.evictCh:
			entry.done <- a.writeEviction(entry)
		case entry, open := <-a.queue:
			if !open {
				a.writeSummary()
				// The last record of a clean stop; after it nothing is
				// written, so a start that finds another reconciles.
				a.write([]*auditEntry{{event: a.stamp(Event{Kind: closedKind}), done: make(chan error, 1)}})
				if a.file != nil {
					a.fileErr = a.closeFile()
				}
				return
			}
			batch = a.fill(a.take(batch[:0], entry))
			if a.window > 0 && len(batch) > 1 {
				batch = a.gather(batch, window)
			}
			if len(batch) > 0 {
				a.settle(batch, a.write(batch))
			}
			// Cleared, so finished events are not kept reachable.
			clear(batch[:cap(batch)])
		case <-tick.C:
			a.writeSummary()
		case <-checkpoints.C:
			if e, ok := a.checkpoint(a.head); ok {
				a.write([]*auditEntry{{event: e, done: make(chan error, 1)}})
			}
		case <-retry.C:
			switch {
			case a.down.Load():
				a.replace()
			case a.noSpace.Load():
				a.retrySpace()
			}
		}
	}
}

// take adds entry to batch unless its Commit withdrew it; a withdrawn entry
// is no longer accepted and is never written.
func (a *AuditLog) take(batch []*auditEntry, entry *auditEntry) []*auditEntry {
	if entry.done != nil && !entry.state.CompareAndSwap(entryQueued, entryTaken) {
		a.accepted.Add(^uint64(0))
		return batch
	}
	return append(batch, entry)
}

// settle counts a written batch and acknowledges its waiting entries with
// err. A batch refused for want of room (files or space) is no longer
// accepted, as at a full queue; write counted those nobody waits for as lost.
func (a *AuditLog) settle(batch []*auditEntry, err error) {
	switch {
	case err == nil:
		a.written.Add(uint64(len(batch)))
	case errors.Is(err, errStorageFull), errors.Is(err, errNoSpace), errors.Is(err, errDown):
		a.accepted.Add(-uint64(len(batch)))
	}
	for _, entry := range batch {
		if entry.done != nil {
			entry.done <- err
		}
	}
}

// fill adds the events already queued to batch, up to auditBatchSize.
func (a *AuditLog) fill(batch []*auditEntry) []*auditEntry {
	for len(batch) < auditBatchSize {
		select {
		case entry, open := <-a.queue:
			if !open {
				return batch
			}
			batch = a.take(batch, entry)
		default:
			return batch
		}
	}
	return batch
}

// gather adds events arriving within the sync window to batch, up to
// auditBatchSize, so they share its sync: a burst costs one sync instead of
// one per arrival. Only a batch that already has siblings waits; a lone
// event is synced at once (PostgreSQL's commit_siblings). No event is
// acknowledged before the sync that covers it.
func (a *AuditLog) gather(batch []*auditEntry, window *time.Timer) []*auditEntry {
	window.Reset(a.window)
	for len(batch) < auditBatchSize {
		select {
		case entry, open := <-a.queue:
			if !open {
				return batch
			}
			batch = a.take(batch, entry)
		case <-window.C:
			return batch
		}
	}
	window.Stop()
	return batch
}

// writeSummary writes the ingress refusals counted since the last summary.
// When the log refuses it, its counts join the pending loss count, which a
// later write or Close reports.
func (a *AuditLog) writeSummary() {
	e, ok := a.takeSummary()
	if !ok {
		return
	}
	summary := []*auditEntry{{event: a.stamp(e)}}
	err := a.write(summary)
	if err != nil && !errors.Is(err, errStorageFull) && !errors.Is(err, errNoSpace) && !errors.Is(err, errDown) {
		a.lost.Add(unacknowledged(summary))
	}
}

// write writes batch at the end of the log, after a pending rotation marker
// and the pending loss count, and syncs it. Records are numbered as they are
// encoded, so seq rises by one in file order. When a rotation is due and
// the active folder is full under FullRefuse, the file system has no space,
// or the active file is being replaced, the batch is refused and its
// unacknowledged events are counted as lost; any other failure replaces the
// active file (recover.go).
func (a *AuditLog) write(batch []*auditEntry) error {
	if a.failed.Load() {
		return errAuditFailed
	}
	if a.noSpace.Load() {
		a.lost.Add(unacknowledged(batch))
		return errNoSpace
	}
	if a.down.Load() {
		a.lost.Add(unacknowledged(batch))
		return errDown
	}
	return a.writeBatch(batch)
}

// writeBatch is write without the refusal of a log that has no space, which
// retrySpace uses to try again.
func (a *AuditLog) writeBatch(batch []*auditEntry) error {
	mark := a.seq
	rotatedNow := false
	lost := a.lost.Swap(0)
	buffer := a.encode(a.encoded[:0], lost, batch)
	if a.size > 0 && a.size+int64(len(buffer)) > a.maxBytes {
		a.seq = mark
		if err := a.makeRoom(); errors.Is(err, errFull) {
			a.lost.Add(lost + unacknowledged(batch))
			a.markFull(err)
			return errStorageFull
		} else if err != nil {
			a.lost.Add(lost + unacknowledged(batch))
			return a.failWrite(err, "rotation_failed")
		}
		rotated, err := a.rotate()
		if err != nil {
			// The count was not written, so it stays pending.
			a.lost.Add(lost + unacknowledged(batch))
			return a.failWrite(err, "rotation_failed")
		}
		a.marker = rotated
		rotatedNow = true
		a.full.Store(false)
		mark = a.seq
		buffer = a.encode(buffer[:0], lost, batch)
	}
	var cp *Checkpoint
	for _, entry := range batch {
		if entry.event.Kind == "audit.checkpoint" {
			cp = &Checkpoint{
				Boot:      a.boot,
				SHA256:    entry.event.Digest,
				Kid:       entry.event.Target,
				Signature: entry.event.Signature,
				Time:      entry.event.Time,
			}
		}
	}
	if rotatedNow && a.marker != "" {
		// The head of the file just closed, signed at rotation.
		if e, ok := a.checkpoint(a.head); ok {
			buffer = a.appendEvent(buffer, e)
			cp = &Checkpoint{
				Boot:      a.boot,
				SHA256:    e.Digest,
				Kid:       e.Target,
				Signature: e.Signature,
				Time:      e.Time,
			}
		}
	}
	buffer, head := a.chain(buffer, a.head)
	err := a.persist(buffer)
	if err != nil && spaceError(err) && a.releaseReserve() {
		err = a.persist(buffer)
	}
	if err != nil {
		a.seq = mark
		a.lost.Add(lost)
		a.lost.Add(unacknowledged(batch))
		if spaceError(err) {
			a.enterNoSpace(err)
			return errNoSpace
		}
		return a.failWrite(err, "sync_failed")
	}
	a.marker = ""
	a.fresh = false
	a.lossTotal.Add(lost)
	a.head = head
	a.chainBatches.Add(1)
	if cp != nil {
		a.lastCheckpoint.Store(cp)
	}
	// A rare huge batch is not kept: memory stays bounded by ordinary batches.
	if cap(buffer) <= keptBatchBytes {
		a.encoded = buffer
	}
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
func unacknowledged(batch []*auditEntry) uint64 {
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
