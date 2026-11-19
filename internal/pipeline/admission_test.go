// The admission record through the real handler and audit log.

package pipeline

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// The admission record is written only once AUDIT passed, so it says PASS.
func TestAdmissionRecordsAuditPass(t *testing.T) {
	_, records, _ := exchange(t, setup{ops: []policy.Operation{public("GET", "/a/x")}}, httptest.NewRequest(http.MethodGet, "/a/x", nil))
	if len(records) != 2 || records[0]["kind"] != "request.admitted" {
		t.Fatalf("records %v", records)
	}
	stages, _ := records[0]["stages"].(map[string]any)
	if stages["AUDIT"] != audit.StagePass {
		t.Fatalf("admission AUDIT %v, want PASS", stages["AUDIT"])
	}
}
