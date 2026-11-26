// Admission checks before the local Max-Forwards 0 answer on OPTIONS requests.

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

func TestMaxForwardsAfterAdmissionChecks(t *testing.T) {
	forwarded := 0
	p := policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}},
		APIs: []policy.API{
			{ID: "main", Upstream: "A", AllowAddresses: []string{"127.0.0.1/32"}},
			{ID: "restricted", Upstream: "A", AllowAddresses: []string{"198.51.100.0/24"}},
		},
		Roles: []policy.Role{{ID: "READER"}},
		Operations: []policy.Operation{
			{ID: "restricted.get", API: "restricted", Method: http.MethodGet, Target: "/restricted/secret", Access: "allow", Auth: "required"},
			{ID: "restricted.opt", API: "restricted", Method: http.MethodOptions, Target: "/restricted/open", Access: "allow", Auth: "none"},
			{ID: "main.deny.get", API: "main", Method: http.MethodGet, Target: "/d", Access: "deny", Auth: "none"},
			{ID: "main.deny.opt", API: "main", Method: http.MethodOptions, Target: "/d-opt", Access: "deny", Auth: "none"},
			{ID: "main.auth.opt", API: "main", Method: http.MethodOptions, Target: "/a/protected", Access: "allow", Auth: "required"},
			{
				ID: "main.rate.opt", API: "main", Method: http.MethodOptions, Target: "/a/limited",
				Access: "allow", Auth: "none",
				Rate: &policy.RateRule{Algorithm: compile.RateAlgorithm, Count: 1, WindowSeconds: 60, Key: compile.RateKeyAddress},
			},
			{ID: "main.ok.get", API: "main", Method: http.MethodGet, Target: "/a/o", Access: "allow", Auth: "none"},
			{ID: "main.ok.opt", API: "main", Method: http.MethodOptions, Target: "/a/o", Access: "allow", Auth: "none"},
		},
		Permits: []policy.Permit{
			{Role: "READER", Operation: "restricted.get"},
			{Role: "READER", Operation: "main.auth.opt"},
		},
	}
	g, err := compile.Compile(p, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	log := audit.OpenAudit(t.TempDir()+"/audit.log", audit.Settings{MaxBytes: 1 << 20, MaxFiles: 2})
	t.Cleanup(func() { _ = log.Close(t.Context()) })
	h, err := New(Deps{
		Authority:    fixedAuthority{g},
		Audit:        log,
		Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs),
		Limiter:      NewLimiter(policy.DefaultRateCounters),
		Clock:        NewClock(),
		AuditTimeout: time.Second,
		Forward: func(w http.ResponseWriter, _ *http.Request) error {
			forwarded++
			w.WriteHeader(http.StatusOK)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	send := func(target, mf string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodOptions, target, nil)
		req.RemoteAddr = "127.0.0.1:40000"
		if mf != "" {
			req.Header.Set("Max-Forwards", mf)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	cases := []struct {
		name       string
		target     string
		wantStatus int
		wantCode   string
	}{
		{"outside allow_addresses without OPTIONS op", "/restricted/secret", http.StatusMethodNotAllowed, "method_not_allowed"},
		{"outside allow_addresses with OPTIONS op", "/restricted/open", http.StatusForbidden, "address_not_allowed"},
		{"access deny without OPTIONS op", "/d", http.StatusMethodNotAllowed, "method_not_allowed"},
		{"access deny with OPTIONS op", "/d-opt", http.StatusForbidden, "forbidden"},
		{"protected OPTIONS without token", "/a/protected", http.StatusUnauthorized, "unauthenticated"},
	}
	for _, tc := range cases {
		plain := send(tc.target, "")
		if plain.Code != tc.wantStatus {
			t.Fatalf("%s without Max-Forwards: status %d, want %d", tc.name, plain.Code, tc.wantStatus)
		}
		mf := send(tc.target, "0")
		if mf.Code != tc.wantStatus || !strings.Contains(mf.Body.String(), tc.wantCode) {
			t.Errorf("%s with Max-Forwards 0: status %d body %q, want %d %q", tc.name, mf.Code, mf.Body.String(), tc.wantStatus, tc.wantCode)
		}
	}

	// Rate-limited OPTIONS route: first admitted locally (204), second refused 429.
	if rec := send("/a/limited", "0"); rec.Code != http.StatusNoContent {
		t.Fatalf("first rate-limited Max-Forwards 0: status %d, want 204", rec.Code)
	}
	if rec := send("/a/limited", "0"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("second rate-limited Max-Forwards 0: status %d, want 429", rec.Code)
	}

	// Admitted OPTIONS route: answered locally with Allow and never forwarded.
	if rec := send("/a/o", "0"); rec.Code != http.StatusNoContent || !strings.Contains(rec.Header().Get("Allow"), "GET") || !strings.Contains(rec.Header().Get("Allow"), "OPTIONS") {
		t.Errorf("admitted Max-Forwards 0: status %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
	if forwarded != 0 {
		t.Errorf("forwarded %d requests, want 0", forwarded)
	}
}

// OPTIONS with Max-Forwards 0 is answered by the gateway with the target's
// methods once the route admits it; a larger value is decremented; anything
// else is refused. Other methods forward the field unchanged.
func TestMaxForwards(t *testing.T) {
	var seen string
	getO := public("GET", "/a/o")
	getO.ID = "get-o"
	s := setup{ops: []policy.Operation{public("GET", "/a/x"), getO, public("OPTIONS", "/a/o")}, forward: func(w http.ResponseWriter, r *http.Request) error {
		seen = r.Header.Get("Max-Forwards")
		w.WriteHeader(http.StatusOK)
		return nil
	}}
	request := func(method, target, value string) *http.Request {
		r := httptest.NewRequest(method, target, nil)
		r.Header.Set("Max-Forwards", value)
		return r
	}
	if rec, _, _ := exchange(t, s, request(http.MethodOptions, "/a/x", "0")); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Max-Forwards 0 without OPTIONS op: %d, want 405", rec.Code)
	}
	rec, records, _ := exchange(t, s, request(http.MethodOptions, "/a/o", "0"))
	if e := last(records); rec.Code != http.StatusNoContent || !strings.Contains(rec.Header().Get("Allow"), "GET") || e["kind"] != "request.preflight" || e["error"] != "max_forwards" || !quick(e) {
		t.Fatalf("Max-Forwards 0: %d %v %v", rec.Code, rec.Header(), e)
	}
	for _, tc := range []struct{ method, target, value, want string }{{"OPTIONS", "/a/o", "5", "4"}, {"OPTIONS", "/a/o", "1", "0"}, {"GET", "/a/x", "0", "0"}} {
		seen = ""
		if rec, _, _ := exchange(t, s, request(tc.method, tc.target, tc.value)); rec.Code != http.StatusOK || seen != tc.want {
			t.Errorf("%s %s: %d, forwarded %q, want %q", tc.method, tc.value, rec.Code, seen, tc.want)
		}
	}
	for _, value := range []string{"x", "-1", "+2", "1, 2", ""} {
		rec, records, _ := exchange(t, s, request(http.MethodOptions, "/a/o", value))
		if e := last(records); rec.Code != http.StatusBadRequest || e["reason"] != "max_forwards" {
			t.Errorf("%q: %d %v", value, rec.Code, e)
		}
	}
}
