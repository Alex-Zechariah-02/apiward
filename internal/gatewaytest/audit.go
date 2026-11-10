// Reading the security log a deployment wrote: its records, the events of
// one request and the stages they reached.

package gatewaytest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// AuditEvents reads every record of the deployment's audit log.
func (e *Env) AuditEvents() []map[string]any {
	e.T.Helper()
	data, err := os.ReadFile(e.AuditLog)
	if err != nil {
		e.T.Fatal(err)
	}
	events, err := ParseAudit(data, filepath.Base(e.AuditLog))
	if err != nil {
		e.T.Fatal(err)
	}
	return events
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
			events = append(events, ev)
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

// EventsWhen waits until the audit log satisfies done. Events that do not
// gate a decision are written asynchronously, so they may land shortly after
// the response.
func (e *Env) EventsWhen(done func([]map[string]any) bool) []map[string]any {
	e.T.Helper()
	limit := time.Now().Add(5 * time.Second)
	for {
		events := e.AuditEvents()
		if done(events) || time.Now().After(limit) {
			return events
		}
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

// AuditLines reads every record of an audit file.
func AuditLines(t *testing.T, path string) []AuditLine {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var events []AuditLine
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e AuditLine
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line is not one record: %q", line)
		}
		events = append(events, e)
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

// ExpectedStages builds the full stage map for a request event: the listed
// stages passed, the terminal stage has the given result, and every other
// stage was not evaluated.
func ExpectedStages(passed []string, terminal, result string) map[string]any {
	stages := map[string]any{}
	for _, name := range audit.StageNames {
		stages[name] = audit.StageNotRun
	}
	for _, name := range passed {
		stages[name] = audit.StagePass
	}
	if terminal != "" {
		stages[terminal] = result
	}
	return stages
}

// Public marks the authentication and rate stages of a public operation as
// not applicable: it reads no token and cannot carry a rate rule.
func Public(stages map[string]any) map[string]any {
	stages["JWT"] = audit.StageNotApplicable
	stages["RBAC"] = audit.StageNotApplicable
	stages["RATE"] = audit.StageNotApplicable
	return stages
}

// RequestID returns a data-plane response's status and the request_id its
// JSON body names, empty when the body names none.
func RequestID(resp *http.Response, body string) (int, string) {
	var reply struct {
		RequestID string `json:"request_id"`
	}
	json.Unmarshal([]byte(body), &reply)
	return resp.StatusCode, reply.RequestID
}

// SameStages reports whether two stage maps encode to the same JSON.
func SameStages(got any, want map[string]any) bool {
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	return bytes.Equal(a, b)
}

// IngressSummary stops the gateway gracefully, so it writes the ingress
// refusals counted since its last summary, and returns every summary's
// counts by reason. The gateway must have been started Interruptible.
func (e *Env) IngressSummary() map[string]int {
	e.T.Helper()
	Interrupt(e.T, e.Process)
	if code := e.WaitExit(); code != ExitStopped {
		e.T.Fatalf("exit status %d\n%s", code, e.Output)
	}
	return SummaryCounts(e.AuditEvents())
}

// SummaryCounts adds up the ingress summaries among events by reason.
func SummaryCounts(events []map[string]any) map[string]int {
	counts := map[string]int{}
	for _, ev := range events {
		if ev["kind"] != "audit.ingress_summary" {
			continue
		}
		reasons, _ := ev["counts"].(map[string]any)
		for reason, n := range reasons {
			count, _ := n.(float64)
			counts[reason] += int(count)
		}
	}
	return counts
}

// RecordOf returns a record of one of the requests ids among events, or nil
// when none has one.
func RecordOf(events []map[string]any, ids []string) map[string]any {
	wanted := map[any]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	for _, ev := range events {
		if wanted[ev["request_id"]] {
			return ev
		}
	}
	return nil
}
