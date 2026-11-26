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
	"slices"
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

// budgetPolicy is the policy of the budget tests: public reads on API a and
// one operation that needs a token and checks its body.
func budgetPolicy() policy.Policy {
	return policy.Policy{
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
	}
}

// serveRecorded sends count requests from one client address through a
// handler for p and returns their statuses and the security log's records.
func serveRecorded(t *testing.T, p policy.Policy, v *Verifier, count int, makeReq func() *http.Request) ([]int, []map[string]any) {
	t.Helper()
	g, err := compile.Compile(p, 1, time.Time{}, policy.Limits{})
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
	var codes []int
	for range count {
		rec := httptest.NewRecorder()
		req := makeReq()
		req.RemoteAddr = "203.0.113.10:12345"
		h.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if err := log.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var events []map[string]any
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var ev map[string]any
		if json.Unmarshal(scanner.Bytes(), &ev) == nil {
			events = append(events, ev)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return codes, events
}

// kindOf returns the records of one kind, in log order.
func kindOf(events []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, ev := range events {
		if ev["kind"] == kind {
			out = append(out, ev)
		}
	}
	return out
}

func runBudgetRequests(t *testing.T, v *Verifier, count int, makeReq func() *http.Request, wantStatus int) ([]map[string]any, map[string]any) {
	t.Helper()
	codes, events := serveRecorded(t, budgetPolicy(), v, count, makeReq)
	for i, code := range codes {
		if code != wantStatus {
			t.Fatalf("request %d: status = %d, want %d", i, code, wantStatus)
		}
	}
	var summary map[string]any
	if summaries := kindOf(events, "audit.ingress_summary"); len(summaries) > 0 {
		summary = summaries[len(summaries)-1]
	}
	return kindOf(events, "request.rejected"), summary
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

func TestBadMaxForwardsRefusalsShareAddressBudget(t *testing.T) {
	rejected, summary := runBudgetRequests(t, nil, 70, func() *http.Request {
		req := httptest.NewRequest(http.MethodOptions, "/a/item", nil)
		req.Header.Set("Max-Forwards", "1, 2")
		return req
	}, http.StatusBadRequest)
	assertBudgeted(t, rejected, summary, "ROUTE", "bad_request", "ROUTE/max_forwards/")
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

// The preflights of an API whose operations all need a token take the
// strictest of their rate rules, per client address, and its refused
// preflights share the address's refusal budget.
func TestTokenAPIPreflightsRateLimitedAndBudgeted(t *testing.T) {
	strict := &policy.RateRule{Algorithm: compile.RateAlgorithm, Count: 3, WindowSeconds: 60, Key: compile.RateKeySubject}
	loose := &policy.RateRule{Algorithm: compile.RateAlgorithm, Count: 5, WindowSeconds: 60, Key: compile.RateKeySubject}
	cors := &policy.CORS{Origins: []string{"https://shop.example.com"}, Methods: []string{http.MethodGet}}
	token := func(id, api, target string, rate *policy.RateRule) policy.Operation {
		return policy.Operation{ID: id, API: api, Method: http.MethodGet, Target: target, Access: "allow", Auth: "required", Rate: rate}
	}
	p := policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}},
		APIs:          []policy.API{{ID: "a", Upstream: "A", CORS: cors}, {ID: "b", Upstream: "A", CORS: cors}},
		Roles:         []policy.Role{{ID: "customer"}},
		Permits:       []policy.Permit{{Role: "customer", Operation: "items"}, {Role: "customer", Operation: "orders"}, {Role: "customer", Operation: "tickets"}},
		Operations:    []policy.Operation{token("items", "a", "/a/items", loose), token("orders", "a", "/a/orders", strict), token("tickets", "b", "/b/tickets", nil)},
	}
	preflight := func(path, origin string) func() *http.Request {
		return func() *http.Request {
			req := httptest.NewRequest(http.MethodOptions, path, nil)
			req.Header.Set("Origin", origin)
			req.Header.Set("Access-Control-Request-Method", http.MethodGet)
			return req
		}
	}

	codes, _ := serveRecorded(t, p, nil, 5, preflight("/a/items", "https://shop.example.com"))
	if want := []int{204, 204, 204, 429, 429}; !slices.Equal(codes, want) {
		t.Errorf("preflights of a token API: %v, want %v", codes, want)
	}

	codes, events := serveRecorded(t, p, nil, 70, preflight("/b/tickets", "https://other.example.com"))
	for i, code := range codes {
		if code != http.StatusNoContent {
			t.Fatalf("refused preflight %d: status %d, want 204", i, code)
		}
	}
	if full := len(kindOf(events, "request.preflight")); full != 60 {
		t.Errorf("refused preflights recorded in full: %d, want 60", full)
	}
	summaries := kindOf(events, "audit.ingress_summary")
	if len(summaries) == 0 {
		t.Fatal("no audit.ingress_summary record")
	}
	counts, _ := summaries[len(summaries)-1]["counts"].(map[string]any)
	if counts["ROUTE/cors_refused/tickets"] != float64(10) {
		t.Errorf("summary counts %v, want 10 under ROUTE/cors_refused/tickets", counts)
	}
}
