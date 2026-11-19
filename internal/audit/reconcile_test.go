// After an unclean stop the next start marks the admissions without an
// outcome as unknown; a clean stop ends the file with audit.closed.

package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUncleanStopMarksUnknownOutcomes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	now := time.Now().UTC()
	line := func(kind, id string, at time.Time) string {
		return `{"schema":8,"time":"` + at.Format(time.RFC3339Nano) + `","seq":1,"kind":"` + kind + `","request_id":"` + id + `","operation":"read"}` + "\n"
	}
	// a: admitted and forwarded; b: admitted only; c: admitted then refused
	// at AUDIT; d: admitted only, but long before the window.
	crashed := line("request.admitted", "d", now.Add(-time.Hour)) + line("request.admitted", "a", now) + line("request.forwarded", "a", now) +
		line("request.admitted", "b", now) + line("request.admitted", "c", now) + line("request.rejected", "c", now)
	if err := os.WriteFile(path, []byte(crashed), 0o600); err != nil {
		t.Fatal(err)
	}
	a := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 2, Append: true, OutcomeWindow: time.Minute})
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	var unknown []string
	reconciled, closed := 0, false
	for _, e := range records(t, path) {
		switch e.Kind {
		case "request.outcome_unknown":
			unknown = append(unknown, e.RequestID)
		case "audit.reconciled":
			reconciled++
			if e.Counts["outcome_unknown"] != 1 {
				t.Fatalf("reconciled counts %v", e.Counts)
			}
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	closed = strings.Contains(string(data), `"kind":"audit.closed"`)
	if len(unknown) != 1 || unknown[0] != "b" || reconciled != 1 || !closed {
		t.Fatalf("unknown %v, reconciled %d, closed %v", unknown, reconciled, closed)
	}
	// The clean stop above ended with audit.closed: a second start adds no
	// reconciliation.
	again := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 2, Append: true, OutcomeWindow: time.Minute})
	if err := again.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range records(t, path) {
		if e.Kind == "audit.reconciled" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d reconciliations after a clean stop", count)
	}
}
