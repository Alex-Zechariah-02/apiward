// A panic inside enforcement still leaves a truthful outcome record.

package pipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// panicAuthority panics when a request captures the published generation.
type panicAuthority struct{ noAuthority }

func (panicAuthority) Current() *compile.Generation { panic("broken authority") }

func TestPanicLeavesFailedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log := audit.OpenAudit(path, audit.Settings{MaxBytes: 1 << 20, MaxFiles: 2})
	forward := func(http.ResponseWriter, *http.Request) error { return nil }
	h, err := New(Deps{Authority: panicAuthority{}, Audit: log, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(policy.DefaultRateCounters), Clock: NewClock(), Forward: forward})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/items", nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "internal_error") {
		t.Fatalf("response %d %s, want 500 internal_error", rec.Code, rec.Body)
	}
	if err := log.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Kind, Decision, Reason string
		Status                 int
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &e); err != nil {
		t.Fatalf("records %s: %v", data, err)
	}
	if e.Kind != "request.rejected" || e.Decision != "failed" || e.Reason != "internal_error" || e.Status != http.StatusInternalServerError {
		t.Fatalf("record %+v, want a failed internal_error outcome", e)
	}
}
