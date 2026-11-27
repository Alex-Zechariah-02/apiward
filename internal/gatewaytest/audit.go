// Reading the security log a deployment wrote: its records, the events of
// one request and the stages they reached.

package gatewaytest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// LogOwn reports the log's own bookkeeping records (the chain, its
// checkpoints and a clean stop's mark), which the readers below leave out:
// the audit package's tests check them.
func LogOwn(kind string) bool {
	return kind == "audit.chain" || kind == "audit.checkpoint" || kind == "audit.closed"
}

// readLiveAudit reads the active audit file up to its logical end without
// blocking Windows renames or scanning a Linux prefill zero tail.
func readLiveAudit(path string) ([]byte, error) {
	file, err := audit.OpenShared(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	end, err := audit.End(file)
	if err != nil || end == 0 {
		return nil, err
	}
	data := make([]byte, end)
	n, err := file.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return data[:n], nil
}

// AuditEvents reads every record of the deployment's audit log but its own
// bookkeeping records (LogOwn).
func (e *Env) AuditEvents() []map[string]any {
	e.T.Helper()
	data, err := readLiveAudit(e.AuditLog)
	if err != nil {
		e.T.Fatal(err)
	}
	events, err := ParseAudit(data, filepath.Base(e.AuditLog))
	if err != nil {
		e.T.Fatal(err)
	}
	return events
}

// RotatedAudit returns the paths of the rotated files of the audit log at
// active, in its folder and in the default archive folder beside it, oldest
// first.
func RotatedAudit(t *testing.T, active string) []string {
	t.Helper()
	rotated, err := audit.RotatedFiles(active, filepath.Join(filepath.Dir(active), "archive"))
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(rotated))
	for _, file := range rotated {
		paths = append(paths, file.Path())
	}
	return paths
}

// ReadAudit reads an audit file's content, decompressing an archived one.
func ReadAudit(t *testing.T, path string) []byte {
	t.Helper()
	reader, err := audit.OpenRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return audit.Content(data)
}

// ParseAudit decodes the records of the audit file named file. The gateway
// may be appending while it is read, so an unterminated tail is a record
// still being written and is skipped. A record a crash cut short stays in the
// file, ended by the next start, which names its offset in an audit.recovered
// record; only such a line may fail to decode.
func ParseAudit(data []byte, file string) ([]map[string]any, error) {
	data = data[:bytes.LastIndexByte(data, '\n')+1]
	var events []map[string]any
	var broken []int
	recovered := map[int]bool{}
	for offset := 0; offset < len(data); {
		end := offset + bytes.IndexByte(data[offset:], '\n')
		line := data[offset:end]
		var ev map[string]any
		switch {
		case len(bytes.TrimSpace(line)) == 0:
		case json.Unmarshal(line, &ev) != nil:
			broken = append(broken, offset)
		default:
			if at, ok := ev["offset"].(float64); ok && ev["kind"] == "audit.recovered" && ev["file"] == file {
				recovered[int(at)] = true
			}
			if kind, _ := ev["kind"].(string); !LogOwn(kind) {
				events = append(events, ev)
			}
		}
		offset = end + 1
	}
	for _, at := range broken {
		if !recovered[at] {
			end := at + bytes.IndexByte(data[at:], '\n')
			return nil, fmt.Errorf("audit line is not one JSON record: %q", data[at:end])
		}
	}
	return events, nil
}

// auditWait bounds EventsWhen: the writer flushes a batch within
// milliseconds, so 5 s is far above it even on a loaded CI runner.
const auditWait = 5 * time.Second

// EventsWhen waits until the audit log satisfies done and fails the test
// when it does not within auditWait. Events that do not gate a decision are
// written asynchronously, so they may land shortly after the response; a
// concurrent WriteAt into a prefilled Linux file can also tear one read, so
// transient parse errors retry until auditWait and fail if they persist.
func (e *Env) EventsWhen(done func([]map[string]any) bool) []map[string]any {
	e.T.Helper()
	limit := time.Now().Add(auditWait)
	var lastErr error
	var count int
	for {
		data, err := readLiveAudit(e.AuditLog)
		if err == nil {
			var events []map[string]any
			events, err = ParseAudit(data, filepath.Base(e.AuditLog))
			if err == nil {
				count = len(events)
				if done(events) {
					return events
				}
			}
		}
		lastErr = err
		if time.Now().After(limit) {
			if lastErr != nil {
				e.T.Fatalf("the audit log did not become readable within %s: %v", auditWait, lastErr)
			}
			e.T.Fatalf("the audit log did not reach the awaited state within %s (%d records)", auditWait, count)
		}
		// Each pass re-reads the active file; 20 ms keeps that cheap.
		time.Sleep(20 * time.Millisecond)
	}
}

// CountKind counts the events of one kind.
func CountKind(events []map[string]any, kind string) int {
	n := 0
	for _, ev := range events {
		if ev["kind"] == kind {
			n++
		}
	}
	return n
}

// HasKinds reports whether events holds at least one event of every kind.
func HasKinds(events []map[string]any, kinds ...string) bool {
	for _, kind := range kinds {
		if CountKind(events, kind) == 0 {
			return false
		}
	}
	return true
}

// AuditLine is what the restart tests read of one audit record.
type AuditLine struct {
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
	Seq       uint64 `json:"seq"`
	Lost      uint64 `json:"lost"`
}

// AuditLines reads every record of an audit file, up to its logical end.
func AuditLines(t *testing.T, path string) []AuditLine {
	t.Helper()
	var events []AuditLine
	for _, line := range strings.Split(strings.TrimSpace(string(ReadAudit(t, path))), "\n") {
		if line == "" {
			continue
		}
		var e AuditLine
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line is not one record: %q", line)
		}
		if !LogOwn(e.Kind) {
			events = append(events, e)
		}
	}
	return events
}

// RequestEvents waits for and returns the events of one request.
func (e *Env) RequestEvents(requestID string, want int) []map[string]any {
	e.T.Helper()
	events := e.EventsWhen(func(events []map[string]any) bool {
		n := 0
		for _, ev := range events {
			if ev["request_id"] == requestID {
				n++
			}
		}
		return n >= want
	})
	var mine []map[string]any
	for _, ev := range events {
		if ev["request_id"] == requestID {
			mine = append(mine, ev)
		}
	}
	return mine
}
