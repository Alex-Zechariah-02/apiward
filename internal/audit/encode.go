// Encoding a batch: numbering each record in file order and bounding its
// size, so recovery always finds the start of the last record.

package audit

import "log/slog"

// encode appends the pending rotation marker, the loss record for lost and
// the events of batch to buffer, numbering each.
func (a *AuditLog) encode(buffer []byte, lost uint64, batch []*auditEntry) []byte {
	if a.marker != "" {
		buffer = a.appendEvent(buffer, a.stamp(Event{Kind: "audit.rotated", File: a.marker}))
	}
	if lost > 0 {
		buffer = a.appendEvent(buffer, a.stamp(Event{Kind: "audit.loss", Lost: lost}))
	}
	for _, entry := range batch {
		buffer = a.appendEvent(buffer, entry.event)
	}
	return buffer
}

// keptBatchBytes bounds the batch memory the writer keeps for reuse: about
// 128 ordinary records.
const keptBatchBytes = 256 << 10

// appendEvent numbers e and appends it as one JSON line (appendRecord: no
// reflection, no copy). A record that would exceed MaxRecordBytes, which
// recovery relies on, is replaced by an audit.unwritable record that keeps
// its identity and decision and says why.
func (a *AuditLog) appendEvent(buffer []byte, e Event) []byte {
	a.seal(&e)
	start := len(buffer)
	buffer = append(appendRecord(buffer, &e), '\n')
	if len(buffer)-start <= MaxRecordBytes {
		return buffer
	}
	slog.Error("audit record replaced", "kind", e.Kind, "request_id", e.RequestID, "reason", "too_large", "bytes", len(buffer)-start)
	substitute := Event{Schema: e.Schema, ID: e.ID, Time: e.Time, Seq: e.Seq, Kind: "audit.unwritable", RequestID: e.RequestID,
		Stage: e.Stage, Decision: e.Decision, Status: e.Status, Reason: "too_large", Target: e.Kind, Bytes: int64(len(buffer) - start)}
	// Every field of the substitute is bounded.
	return append(appendRecord(buffer[:start], &substitute), '\n')
}
