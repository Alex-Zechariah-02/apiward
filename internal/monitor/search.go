// Security log queries, cursors and results, and the files a search reads.

package monitor

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

const (
	// securityLogWindow bounds the bytes read from disk at once; a page reads
	// at most securityLogPageScan bytes and an export securityLogExportScan,
	// so every answer ends in bounded time and memory however large the files.
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

// auditRequestRecord is the part of a request's audit record the search
// reads; it is projected through requestView like the live views.
type auditRequestRecord struct {
	ID            string            `json:"event_id"`
	Kind          string            `json:"kind"`
	Time          time.Time         `json:"time"`
	RequestID     string            `json:"request_id"`
	Stage         string            `json:"stage"`
	Decision      string            `json:"decision"`
	Status        int               `json:"status"`
	Error         string            `json:"error"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Operation     string            `json:"operation"`
	API           string            `json:"api"`
	Subject       string            `json:"subject"`
	Roles         []string          `json:"roles"`
	ClientAddress string            `json:"client_address"`
	Generation    string            `json:"generation"`
	DurationMS    float64           `json:"duration_ms"`
	Modules       map[string]string `json:"modules"`
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
	for name, value := range map[string]string{"ref": q.ref, "subject": q.subject, "operation": q.operation} {
		if len(value) > policy.MaxIDLength {
			return q, name
		}
	}
	if q.decision != "" && q.decision != "allowed" && q.decision != "refused" && q.decision != "failed" {
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

// LogFiles lists the audit files newest first: the active file, then
// the rotated files from the highest number down. missing names the numbered
// files below the highest that are no longer present (moved away to archive).
func LogFiles(active string) (files, missing []string, err error) {
	entries, err := os.ReadDir(filepath.Dir(active))
	if err != nil {
		return nil, nil, err
	}
	prefix := filepath.Base(active) + "."
	numbers := []int{}
	for _, entry := range entries {
		suffix, found := strings.CutPrefix(entry.Name(), prefix)
		if n, err := strconv.Atoi(suffix); found && err == nil && n >= 1 && strconv.Itoa(n) == suffix {
			numbers = append(numbers, n)
		}
	}
	slices.Sort(numbers)
	files = []string{filepath.Base(active)}
	for i := len(numbers) - 1; i >= 0; i-- {
		files = append(files, prefix+strconv.Itoa(numbers[i]))
	}
	missing = []string{}
	if len(numbers) > 0 {
		for n := 1; n < numbers[len(numbers)-1]; n++ {
			if !slices.Contains(numbers, n) {
				missing = append(missing, prefix+strconv.Itoa(n))
			}
		}
	}
	return files, missing, nil
}
