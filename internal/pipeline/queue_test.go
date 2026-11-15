// An admission whose security record finds no room in the audit queue is
// refused and never forwarded.

package pipeline

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestAuditQueueFullRefuses(t *testing.T) {
	op := policy.Operation{ID: "x", API: "a", Method: "GET", Target: "/a/x", Access: "allow", Auth: "none"}
	g, err := compile.Compile(policy.Policy{
		SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}}, APIs: []policy.API{{ID: "a", Upstream: "A"}},
		Operations: []policy.Operation{op},
	}, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	// A log whose queue has no room at all: every Commit is refused as full.
	full := &audit.AuditLog{}
	forwarded := false
	h, err := New(Deps{Authority: fixedAuthority{g}, Audit: full, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(policy.DefaultRateCounters), Clock: NewClock(), AuditTimeout: time.Second,
		Forward: func(http.ResponseWriter, *http.Request) error {
			forwarded = true
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a/x", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "gateway_unavailable") || forwarded {
		t.Fatalf("answer %d %s, forwarded %v; want 503 gateway_unavailable, not forwarded", rec.Code, rec.Body, forwarded)
	}
}
