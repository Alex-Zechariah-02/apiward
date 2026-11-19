// Policy refusals beyond an address's budget are counted, not recorded.

package audit

import (
	"context"
	"path/filepath"
	"testing"
)

// One address gets refusalRecords full records a minute; the next refusal
// is counted in the summary by stage, reason and operation. Another
// address keeps its own budget.
func TestRefusalBudgetPerAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 2})
	refusal := Event{Kind: "request.rejected", Stage: "JWT", Error: "unauthorized", Reason: "invalid_signature", Operation: "list-orders", ClientAddress: "192.0.2.1"}
	for range refusalRecords + 1 {
		a.RecordRefusal(refusal)
	}
	other := refusal
	other.ClientAddress = "192.0.2.2"
	a.RecordRefusal(other)
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	full, summaries := 0, 0
	for _, e := range records(t, path) {
		switch e.Kind {
		case "request.rejected":
			full++
		case "audit.ingress_summary":
			summaries++
			if e.Counts["JWT/invalid_signature/list-orders"] != 1 || len(e.Addresses) != 1 || e.Addresses[0] != (AddressCount{"192.0.2.1", 1}) {
				t.Fatalf("summary %+v", e)
			}
		}
	}
	if full != refusalRecords+1 || summaries != 1 {
		t.Fatalf("%d full records and %d summaries, want %d and 1", full, summaries, refusalRecords+1)
	}
}
