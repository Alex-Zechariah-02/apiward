// Per-upstream in-flight slot ordering relative to assertion signing.

package pipeline

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// When an upstream's in-flight slots are full, the request is refused
// upstream_busy before signing an identity assertion.
func TestUpstreamSlotBeforeAssertion(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := compile.Compile(policy.Policy{
		SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams:  []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}},
		APIs:       []policy.API{{ID: "a", Upstream: "A"}},
		Operations: []policy.Operation{public("GET", "/a/*")},
	}, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	log := audit.OpenAudit(filepath.Join(t.TempDir(), "audit.log"), audit.Settings{MaxBytes: 1 << 20, MaxFiles: 2})
	t.Cleanup(func() { log.Close(t.Context()) })
	held, release := make(chan struct{}), make(chan struct{})
	h, err := New(Deps{
		Authority:    fixedAuthority{g},
		Audit:        log,
		Observations: monitor.New(policy.DefaultWindow, policy.DefaultAPIs),
		Limiter:      NewLimiter(policy.DefaultRateCounters),
		Clock:        NewClock(),
		AuditTimeout: time.Second,
		Limits:       Limits{MaxInFlightPerUpstream: 1},
		Signer:       signer,
		Forward: func(w http.ResponseWriter, r *http.Request) error {
			if r.URL.Path == "/a/held" {
				close(held)
				<-release
			}
			w.WriteHeader(http.StatusOK)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/a/held", nil))
	}()
	<-held
	// A path that would fail assertion_too_large at BIND must be refused
	// upstream_busy first when no upstream slot is free.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a/"+strings.Repeat("x", MaxAssertionBytes), nil))
	close(release)
	<-firstDone
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "upstream_busy") {
		t.Fatalf("over-slot request with long path: %d %s; want 503 upstream_busy", rec.Code, rec.Body.String())
	}
}
