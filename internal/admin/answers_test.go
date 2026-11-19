// Admin API answers: health by state, revalidation of the policy by its
// ETag, the traffic window's coverage and the request views' decisions.

package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// Health answers 503 while the gateway is unavailable, so a check that reads
// only the status code tells it from a healthy one.
func TestHealthStatusCode(t *testing.T) {
	opened := testServer(openController(t))
	reply := httptest.NewRecorder()
	opened.handleHealth(reply, httptest.NewRequest(http.MethodGet, "/admin/health", nil))
	if reply.Code != http.StatusOK {
		t.Fatalf("an opened gateway: %d %s", reply.Code, reply.Body)
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "issuer.pem")
	if err := os.WriteFile(key, issuer.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	// Prepared but never opened, the controller has no deployment mode.
	c, err := controller.Prepare(controller.Config{
		Database: filepath.Join(dir, "gateway.db"), AuditLog: filepath.Join(dir, "audit.log"), AdminListen: "127.0.0.1:1",
		JWT: pipeline.TrustConfig{Issuer: issuertest.Name, Audience: issuertest.Audience, Keys: []pipeline.VerificationKey{{Kid: "test-a", PublicKeyFile: key}}},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	reply = httptest.NewRecorder()
	(&Server{control: c}).handleHealth(reply, httptest.NewRequest(http.MethodGet, "/admin/health", nil))
	if reply.Code != http.StatusServiceUnavailable || reply.Body.String() == "" {
		t.Fatalf("an unavailable gateway: %d %s", reply.Code, reply.Body)
	}
}

// A client that holds the confirmed policy's ETag is answered 304 without
// the document; any other tag gets the document.
func TestPolicyNotModified(t *testing.T) {
	s := testServer(openController(t))
	get := func(tag string) *httptest.ResponseRecorder {
		reply := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/admin/policy", nil)
		if tag != "" {
			r.Header.Set("If-None-Match", tag)
		}
		s.handlePolicy(reply, r, caller{})
		return reply
	}
	whole := get("")
	tag := whole.Header().Get("ETag")
	if whole.Code != http.StatusOK || tag == "" {
		t.Fatalf("policy: %d, ETag %q", whole.Code, tag)
	}
	for _, held := range []string{tag, "W/" + tag, `"other", ` + tag, "*"} {
		if reply := get(held); reply.Code != http.StatusNotModified || reply.Body.Len() != 0 || reply.Header().Get("ETag") != tag {
			t.Errorf("If-None-Match %s: %d, %d bytes", held, reply.Code, reply.Body.Len())
		}
	}
	if reply := get(`"r999999"`); reply.Code != http.StatusOK || reply.Body.Len() == 0 {
		t.Errorf("a stale tag: %d", reply.Code)
	}
}

// The traffic answer says from when its window is complete: once the ring
// has dropped requests from inside it, the earlier seconds are not counted
// as quiet.
func TestTrafficCoverage(t *testing.T) {
	s := testServer(openController(t))
	read := func() (covers time.Time, complete bool) {
		t.Helper()
		reply := httptest.NewRecorder()
		s.handleTraffic(reply, httptest.NewRequest(http.MethodGet, "/admin/traffic?window=60", nil), caller{})
		var answer struct {
			CoversFrom time.Time `json:"covers_from"`
			Complete   bool      `json:"complete"`
		}
		if reply.Code != http.StatusOK || json.Unmarshal(reply.Body.Bytes(), &answer) != nil {
			t.Fatalf("traffic: %d %s", reply.Code, reply.Body)
		}
		return answer.CoversFrom, answer.Complete
	}
	if _, complete := read(); !complete {
		t.Fatal("an empty window is incomplete")
	}
	now := time.Now().UTC()
	window := s.observations.Window()
	// One more request than the ring holds, spread over the last 30 seconds.
	for i := range window + 1 {
		at := now.Add(-30 * time.Second).Add(time.Duration(i) * 30 * time.Second / time.Duration(window+1))
		s.observations.Record(audit.Event{RequestID: fmt.Sprint(i), Time: at, Decision: "forwarded", Status: 200})
	}
	covers, complete := read()
	if complete || covers.Before(now.Add(-31*time.Second)) || covers.After(now) {
		t.Fatalf("after dropping: covers from %v, complete %t", covers, complete)
	}
}

// The live list accepts every view decision, and the gateway's own failure
// is listed apart from an upstream failure.
func TestEventsDecisionFilter(t *testing.T) {
	s := testServer(openController(t))
	for i, recorded := range []string{"forwarded", "reject", "failed", "upstream_failure"} {
		s.observations.Record(audit.Event{RequestID: fmt.Sprint(i), Time: time.Now(), Decision: recorded, Status: 200})
	}
	for _, filter := range []string{"allowed", "refused", "failed", "upstream_failed"} {
		reply := httptest.NewRecorder()
		s.handleEvents(reply, httptest.NewRequest(http.MethodGet, "/admin/events?decision="+filter, nil), caller{})
		var page struct {
			Items []struct{ Decision string } `json:"items"`
		}
		if reply.Code != http.StatusOK || json.Unmarshal(reply.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].Decision != filter {
			t.Errorf("decision=%s: %d %s", filter, reply.Code, reply.Body)
		}
	}
}

// A gateway whose data plane a host program serves says in its advice that
// it cannot confirm the transport; one that serves it itself does not.
func TestAdviceHostTransport(t *testing.T) {
	c := openController(t)
	for _, hosted := range []bool{false, true} {
		s := New(Deps{Control: c, Limiter: pipeline.NewLimiter(16), Logger: slog.New(slog.DiscardHandler), HostServed: hosted})
		reply := httptest.NewRecorder()
		s.handleAdvice(reply, httptest.NewRequest(http.MethodGet, "/admin/advice", nil), caller{})
		var answer struct {
			Warnings []struct{ ID, Severity string } `json:"warnings"`
		}
		if reply.Code != http.StatusOK || json.Unmarshal(reply.Body.Bytes(), &answer) != nil {
			t.Fatalf("advice: %d %s", reply.Code, reply.Body)
		}
		found := false
		for _, w := range answer.Warnings {
			found = found || (w.ID == "W6" && w.Severity == "info")
		}
		if found != hosted {
			t.Errorf("host served %t: W6 listed %t", hosted, found)
		}
	}
}
