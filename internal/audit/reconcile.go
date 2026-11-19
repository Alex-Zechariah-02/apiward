// Outcomes after a crash. A clean stop ends the active file with
// audit.closed. A start that finds another last record looks back over the
// records written within window of that last one (the longest a request can
// live) and writes request.outcome_unknown for each admission there without
// an outcome, then audit.reconciled with their count, so a reader need not
// infer them by joining records (PostgreSQL marks the transactions a crash
// interrupted as aborted).

package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"time"
)

// closedKind is the last record of a log stopped cleanly.
const closedKind = "audit.closed"

// scanned is what reconciliation reads of one record.
type scanned struct {
	Kind          string    `json:"kind"`
	Time          time.Time `json:"time"`
	RequestID     string    `json:"request_id"`
	Operation     string    `json:"operation"`
	API           string    `json:"api"`
	Subject       string    `json:"subject"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	ClientAddress string    `json:"client_address"`
}

// unfinished returns, in file order, the admissions in path's first end
// bytes written within window of its last record that have no outcome
// (forwarded, rejected or already marked unknown), and whether the file ended
// with audit.closed and its chain record. An empty file counts as closed.
func unfinished(path string, end int64, window time.Duration) ([]scanned, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	var records []scanned
	reader := bufio.NewReaderSize(io.LimitReader(file, end), MaxRecordBytes)
	for {
		line, err := reader.ReadSlice('\n')
		if len(line) > 0 && err == nil {
			var r scanned
			if json.Unmarshal(bytes.TrimSpace(line), &r) == nil {
				records = append(records, r)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil && err != bufio.ErrBufferFull {
			return nil, false, err
		}
	}
	// The chain record that seals the last batch follows audit.closed.
	last := len(records) - 1
	for last >= 0 && records[last].Kind == "audit.chain" {
		last--
	}
	if last < 0 || records[last].Kind == closedKind {
		return nil, true, nil
	}
	cutoff := records[len(records)-1].Time.Add(-window)
	open := map[string]int{}
	var admitted []scanned
	for _, r := range records {
		if r.Time.Before(cutoff) || r.RequestID == "" {
			continue
		}
		switch r.Kind {
		case "request.admitted":
			open[r.RequestID] = len(admitted)
			admitted = append(admitted, r)
		case "request.forwarded", "request.rejected", "request.outcome_unknown":
			if i, ok := open[r.RequestID]; ok {
				admitted[i].RequestID = ""
				delete(open, r.RequestID)
			}
		}
	}
	var pending []scanned
	for _, r := range admitted {
		if r.RequestID != "" {
			pending = append(pending, r)
		}
	}
	return pending, false, nil
}

// reconcile queues the records of an unclean stop: one outcome_unknown per
// unfinished admission and audit.reconciled with their count. Only OpenAudit
// calls it, before the writer starts.
func (a *AuditLog) reconcile(end int64) error {
	pending, closed, err := unfinished(a.path, end, a.outcomeWindow)
	if err != nil || closed {
		return err
	}
	for _, r := range pending {
		a.Record(Event{Kind: "request.outcome_unknown", RequestID: r.RequestID, Decision: "unknown", Operation: r.Operation, API: r.API,
			Subject: r.Subject, Method: r.Method, Path: r.Path, ClientAddress: r.ClientAddress, Reason: "unclean_stop"})
	}
	a.Record(Event{Kind: "audit.reconciled", Counts: map[string]uint64{"outcome_unknown": uint64(len(pending))}})
	return nil
}
