// Stage expectations, summary counts and request-record selectors for audit
// events read from a test deployment.

package gatewaytest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

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
	a, err := json.Marshal(got)
	if err != nil {
		return false
	}
	b, err := json.Marshal(want)
	if err != nil {
		return false
	}
	return bytes.Equal(a, b)
}

// IngressSummary stops the gateway gracefully, so it writes the ingress
// refusals counted since its last summary, and returns every summary's
// counts by reason. The gateway must have been started Interruptible.
func (e *Env) IngressSummary() map[string]int {
	e.T.Helper()
	e.Shutdown()
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

// SummaryRefusals adds up the refusals the ingress summaries among events
// count (keys <STAGE>/<reason>/<operation>), those over a client address's
// budget of recorded refusals a minute.
func SummaryRefusals(events []map[string]any) int {
	total := 0
	for reason, n := range SummaryCounts(events) {
		if strings.Contains(reason, "/") {
			total += n
		}
	}
	return total
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
