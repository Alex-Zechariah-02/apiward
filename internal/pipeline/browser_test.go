// CORS on an API: only an OPTIONS request that carries both Origin and
// Access-Control-Request-Method is answered as a preflight, and the
// gateway's CORS headers replace the upstream's.

package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// An OPTIONS request missing either preflight header is routed like any
// other request, never answered as a CORS preflight.
func TestNearPreflightIsRouted(t *testing.T) {
	cors := &policy.CORS{Origins: []string{"https://shop.example.com"}, Methods: []string{http.MethodGet}}
	p := policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}},
		APIs:          []policy.API{{ID: "a", Upstream: "A", CORS: cors}},
		Operations:    []policy.Operation{public("GET", "/a/items")},
	}
	for _, tc := range []struct {
		name, origin, method string
		preflight            bool
	}{
		{"preflight", "https://shop.example.com", http.MethodGet, true},
		{"no origin", "", http.MethodGet, false},
		{"no requested method", "https://shop.example.com", "", false},
	} {
		_, events := serveRecorded(t, p, nil, 1, func() *http.Request {
			req := httptest.NewRequest(http.MethodOptions, "/a/items", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.method != "" {
				req.Header.Set("Access-Control-Request-Method", tc.method)
			}
			return req
		})
		if answered := len(kindOf(events, "request.preflight")) == 1; answered != tc.preflight {
			t.Errorf("%s: answered as a preflight %v, want %v", tc.name, answered, tc.preflight)
		}
	}
}

// On an API with CORS rules and no response rule, the upstream's own CORS
// headers are replaced by the gateway's for the request's origin.
func TestCORSHeadersReplaced(t *testing.T) {
	cors := &policy.CORS{Origins: []string{"https://shop.example.com"}, Methods: []string{http.MethodGet}}
	g, err := compile.Compile(policy.Policy{
		SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}}, APIs: []policy.API{{ID: "a", Upstream: "A", CORS: cors}},
		Operations: []policy.Operation{public("GET", "/a/items")},
	}, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	log := audit.OpenAudit(filepath.Join(t.TempDir(), "audit.log"), audit.Settings{MaxBytes: 1 << 20, MaxFiles: 2})
	t.Cleanup(func() { log.Close(context.Background()) })
	h, err := New(Deps{Authority: fixedAuthority{g}, Audit: log, Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs), Limiter: NewLimiter(policy.DefaultRateCounters), Clock: NewClock(), AuditTimeout: time.Second,
		Forward: func(w http.ResponseWriter, _ *http.Request) error {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(http.StatusOK)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/a/items", nil)
	req.Header.Set("Origin", "https://shop.example.com")
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); rec.Code != http.StatusOK || got != "https://shop.example.com" {
		t.Fatalf("answer %d with Access-Control-Allow-Origin %q, want 200 with the request's origin", rec.Code, got)
	}
}
