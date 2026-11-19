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
	"time"

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
	t.Cleanup(func() { log.Close(context.Background()) })
	forward := func(http.ResponseWriter, *http.Request) error { return nil }
	h, err := New(Deps{Authority: panicAuthority{}, Audit: log, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(policy.DefaultRateCounters), Clock: NewClock(), AuditTimeout: time.Second, Forward: forward})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/items", nil))
	// Exactly the error and the request ID: no panic value or stack.
	want := `{"error":"internal_error","request_id":"` + rec.Header().Get("X-Request-Id") + "\"}\n"
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != want {
		t.Fatalf("response %d %q, want 500 %q", rec.Code, rec.Body, want)
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
		DurationMS             float64 `json:"duration_ms"`
	}
	// The request's record is the first; the log's own records follow it.
	first, _, _ := strings.Cut(string(data), "\n")
	if err := json.Unmarshal([]byte(first), &e); err != nil {
		t.Fatalf("records %s: %v", data, err)
	}
	if e.Kind != "request.rejected" || e.Decision != "failed" || e.Reason != "internal_error" || e.Status != http.StatusInternalServerError || e.DurationMS < 0 || e.DurationMS > 10_000 {
		t.Fatalf("record %+v, want a failed internal_error outcome", e)
	}
}
