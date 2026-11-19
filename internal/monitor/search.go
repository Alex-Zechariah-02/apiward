// Security log queries, cursors and results, and the files a search reads.

package monitor

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

const (
	// securityLogWindow bounds the bytes read from disk at once; a page reads
	// at most PageScan bytes and an export ExportScan, so every answer ends in
	// bounded time and memory however large the files. A window holds at
	// least 64 records of the largest size (audit.MaxRecordBytes); a page
	// reads four windows; an export reads four audit files of the default
	// size (audit.DefaultAuditBytes) and lists at most as many requests as
	// the live window keeps by default (policy.DefaultWindow).
	securityLogWindow = 4 << 20
	PageScan          = 16 << 20
	ExportScan        = 256 << 20
	ExportRows        = 10000
)

// Query holds the filters of one search. Empty filters match all.
type Query struct {
	ref, subject, operation, decision string
	from, to                          time.Time
}

// auditRequestRecord reads a request's record through the record type
// itself, so the reader and the writer share one definition. The stage
// results are left undecoded: views do not show them.
type auditRequestRecord struct {
	audit.Event
	Stages json.RawMessage `json:"stages"`
}

// decodeRecord decodes a request's record; a record of a newer schema than
// this gateway writes, or without a request ID, is unreadable.
func decodeRecord(line []byte) (audit.Event, bool) {
	var record auditRequestRecord
	if json.Unmarshal(line, &record) != nil || record.RequestID == "" || record.Schema > audit.EventSchema {
		return audit.Event{}, false
	}
	return record.Event, true
}

// Cursor is where a search stopped: lines before offset in the
// file whose first record is first are still to be read. first identifies
// the file across a rotation, which renames the active file.
type Cursor struct {
	File   string `json:"f"`
	First  string `json:"i"`
	Offset int64  `json:"o"`
}

type Result struct {
	Items      []RequestView
	Next       *Cursor
	Searched   []string
	Unreadable int
}

func ParseQuery(values map[string][]string) (Query, string) {
	get := func(name string) string {
		if v := values[name]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	q := Query{ref: strings.ToLower(get("ref")), subject: get("subject"), operation: get("operation"), decision: get("decision")}
	// No record holds a longer value, so a longer filter could match nothing.
	for name, value := range map[string]string{"ref": q.ref, "operation": q.operation} {
		if len(value) > policy.MaxIDLength {
			return q, name
		}
	}
	if len(q.subject) > policy.MaxSubjectLength {
		return q, "subject"
	}
	if q.decision != "" && !slices.Contains(Decisions, q.decision) {
		return q, "decision"
	}
	for name, at := range map[string]*time.Time{"from": &q.from, "to": &q.to} {
		if text := get(name); text != "" {
			parsed, err := time.Parse(time.RFC3339Nano, text)
			if err != nil {
				return q, name
			}
			*at = parsed
		}
	}
	if !q.from.IsZero() && !q.to.IsZero() && q.to.Before(q.from) {
		return q, "to"
	}
	return q, ""
}

func (q Query) matches(view RequestView) bool {
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	return (q.ref == "" || view.RequestID == q.ref) &&
		(q.subject == "" || text(view.Subject) == q.subject) &&
		(q.operation == "" || text(view.Operation) == q.operation) &&
		(q.decision == "" || view.Decision == q.decision) &&
		(q.from.IsZero() || !view.Time.Before(q.from)) &&
		(q.to.IsZero() || view.Time.Before(q.to))
}

// LogFiles lists the audit files newest first: the active file, then the
// rotated files from the newest down. missing names rotated files that are
// no longer present (moved away to archive): each file but the oldest starts
// with an audit.rotated record naming the file rotated before it, and so
// does the oldest while the log holds fewer than limit files (the active one
// included), since before that no file was evicted. The list stays bounded
// by the files present.
func LogFiles(active string, limit int64) (files, missing []string, err error) {
	rotated, err := audit.RotatedFiles(active)
	if err != nil {
		return nil, nil, err
	}
	files = []string{filepath.Base(active)}
	for i := len(rotated) - 1; i >= 0; i-- {
		files = append(files, rotated[i].Name)
	}
	missing = []string{}
	checked := files
	if int64(len(files)) >= limit {
		checked = files[:len(files)-1]
	}
	dir := filepath.Dir(active)
	for _, name := range checked {
		head, err := firstRecord(filepath.Join(dir, name))
		if err != nil || head.Kind != "audit.rotated" || head.File == "" || slices.Contains(files, head.File) {
			continue
		}
		missing = append(missing, head.File)
	}
	return files, missing, nil
}
