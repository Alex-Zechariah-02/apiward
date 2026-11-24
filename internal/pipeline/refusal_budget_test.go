// Tests for the per-address refusal budget on unauthenticated route and
// canonical-path refusals, and full recording of validation refusals.

package pipeline

import (
	"bufio"
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
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

type verifiedAuthority struct {
	fixedAuthority
	verifier *Verifier
}

func (a verifiedAuthority) Verifier() *Verifier { return a.verifier }

func runBudgetRequests(t *testing.T, v *Verifier, count int, makeReq func() *http.Request, wantStatus int) ([]map[string]any, map[string]any) {
	t.Helper()
	g, err := compile.Compile(policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}},
		APIs:          []policy.API{{ID: "a", Upstream: "A"}},
		Roles:         []policy.Role{{ID: "customer"}},
		Permits:       []policy.Permit{{Role: "customer", Operation: "create_item"}},
		Operations: []policy.Operation{
			public(http.MethodGet, "/a/*"),
			{
				ID:     "create_item",
				API:    "a",
				Method: http.MethodPost,
				Target: "/items",
				Access: "allow",
				Auth:   "required",
				Body: &policy.BodyRule{
					MaxBytes: 1024,
					Schema:   json.RawMessage(`{"type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string"}}}`),
				},
			},
		},
	}, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	log := audit.OpenAudit(path, audit.Settings{MaxBytes: 4 << 20, MaxFiles: 4})
	h, err := New(Deps{
		Authority:    verifiedAuthority{fixedAuthority: fixedAuthority{g}, verifier: v},
		Audit:        log,
		Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs),
		Limiter:      NewLimiter(policy.DefaultRateCounters),
		Clock:        NewClock(),
		AuditTimeout: time.Second,
		Forward: func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range count {
		rec := httptest.NewRecorder()
		req := makeReq()
		req.RemoteAddr = "203.0.113.10:12345"
		h.ServeHTTP(rec, req)
		if rec.Code != wantStatus {
			t.Fatalf("status = %d, want %d (body=%s)", rec.Code, wantStatus, rec.Body.String())
		}
	}
	if err := log.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var rejected []map[string]any
	var summary map[string]any
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var ev map[string]any
		if json.Unmarshal(scanner.Bytes(), &ev) != nil {
			continue
		}
		switch ev["kind"] {
		case "request.rejected":
			rejected = append(rejected, ev)
		case "audit.ingress_summary":
			summary = ev
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return rejected, summary
}

func assertBudgeted(t *testing.T, rejected []map[string]any, summary map[string]any, stage, reason, summaryKey string) {
	t.Helper()
	if len(rejected) != 60 {
		t.Fatalf("request.rejected count = %d, want 60", len(rejected))
	}
	for i, ev := range rejected {
		if ev["stage"] != stage || ev["error"] != reason {
			t.Fatalf("record %d: stage=%v error=%v, want %s/%s", i, ev["stage"], ev["error"], stage, reason)
		}
	}
	if summary == nil {
		t.Fatal("expected audit.ingress_summary record")
	}
	counts, _ := summary["counts"].(map[string]any)
	if counts[summaryKey] != float64(10) {
		t.Fatalf("summary counts[%q] = %v, want 10 (all=%v)", summaryKey, counts[summaryKey], counts)
	}
}

func TestRouteRefusalsShareAddressBudget(t *testing.T) {
	rejected, summary := runBudgetRequests(t, nil, 70, func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/no-such-route", nil)
	}, http.StatusNotFound)
	assertBudgeted(t, rejected, summary, "ROUTE", "not_found", "ROUTE/not_found/")
}

func TestMethodRefusalsShareAddressBudget(t *testing.T) {
	rejected, summary := runBudgetRequests(t, nil, 70, func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/a/item", nil)
	}, http.StatusMethodNotAllowed)
	assertBudgeted(t, rejected, summary, "ROUTE", "method_not_allowed", "ROUTE/method_not_allowed/")
}

func TestCanonicalRefusalsShareAddressBudget(t *testing.T) {
	rejected, summary := runBudgetRequests(t, nil, 70, func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/a/../b", nil)
	}, http.StatusBadRequest)
	assertBudgeted(t, rejected, summary, "CANONICAL", "bad_request", "CANONICAL/bad_request/")
}

func TestValidationRefusalsStayFull(t *testing.T) {
	iss := issuertest.New(2048)
	v, err := LoadVerifier(testTrust(issuertest.Name, issuertest.Audience, keyFile(t, iss)))
	if err != nil {
		t.Fatal(err)
	}
	token := iss.Token(t, issuertest.Changed(issuertest.ValidClaims("cust-01"), map[string]any{"roles": []string{"customer"}}))
	rejected, summary := runBudgetRequests(t, v, 70, func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/items", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		return req
	}, http.StatusBadRequest)
	if len(rejected) != 70 {
		t.Fatalf("request.rejected count = %d, want 70", len(rejected))
	}
	for i, ev := range rejected {
		if ev["stage"] != "VALIDATION" {
			t.Fatalf("record %d: stage=%v, want VALIDATION", i, ev["stage"])
		}
	}
	if summary != nil {
		t.Fatalf("expected no audit.ingress_summary, got %v", summary)
	}
}
