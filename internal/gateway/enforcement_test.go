// Enforcement handler helpers, admission and audit gate.

package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// These tests run the enforcement handler under a plain net/http server in
// the test process, with no gateway process. Its forwarder is an in-memory
// stand-in for the reverse proxy that records what it is handed;
// the deployment's real receivers stay connected to nothing, so any request
// reaching them would show a forwarding path outside the handler.

// handedRequest is one admitted request as the forwarder received it.
type handedRequest struct {
	bound  bool // the request carried a trusted binding
	dial   string
	path   string // the bound path the request is forwarded with
	method string
	target string
	host   string
	header http.Header
	body   string
}

// memoryForwarder records every request it is handed and answers with
// respond, or with 200 "forwarded" when respond is nil.
type memoryForwarder struct {
	mu      sync.Mutex
	got     []handedRequest
	respond func(w http.ResponseWriter, r *http.Request) error
}

func (f *memoryForwarder) forward(w http.ResponseWriter, r *http.Request) error {
	dial, path, bound := forward.Bound(r.Context())
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.got = append(f.got, handedRequest{
		bound:  bound,
		dial:   dial,
		path:   path,
		method: r.Method,
		target: r.RequestURI,
		host:   r.Host,
		header: r.Header.Clone(),
		body:   string(body),
	})
	respond := f.respond
	f.mu.Unlock()
	if respond != nil {
		return respond(w, r)
	}
	io.WriteString(w, "forwarded")
	return nil
}

func (f *memoryForwarder) handed() []handedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]handedRequest(nil), f.got...)
}

func (f *memoryForwarder) setRespond(respond func(w http.ResponseWriter, r *http.Request) error) {
	f.mu.Lock()
	f.respond = respond
	f.mu.Unlock()
}

// serveEnforcement seeds e's database with policy, owns its controller and
// serves the enforcement handler, with the global body ceiling maxBodyBytes
// (0: the default), at e.DataAddr, where the harness request helpers send.
func serveEnforcement(e *gatewaytest.Env, policy policy.Policy, maxBodyBytes int64) (*controller.Controller, *pipeline.Handler, *memoryForwarder) {
	e.T.Helper()
	gatewaytest.Seed(e.T, e.Database, policy, gatewaytest.SeedOptions{})
	c, _ := own(e, controllerConfig(e))
	f := &memoryForwarder{}
	h, err := newHandler(c, pipeline.NewLimiter(), maxBodyBytes, f.forward)
	if err != nil {
		e.T.Fatal(err)
	}
	serve(e, h)
	return c, h, f
}

// serveAuthority serves at e.DataAddr the enforcement handler of c that reads
// its published state from authority instead of c.
func serveAuthority(e *gatewaytest.Env, c *controller.Controller, authority pipeline.Authority) *memoryForwarder {
	e.T.Helper()
	f := &memoryForwarder{}
	h, err := pipeline.New(pipeline.Deps{
		Authority: authority, Audit: c.Audit(), Observations: c.Observations(),
		Limiter: pipeline.NewLimiter(), Clock: pipeline.NewClock(), AuditTimeout: c.Settings().AuditTimeout, Forward: f.forward,
	})
	if err != nil {
		e.T.Fatal(err)
	}
	serve(e, h)
	return f
}

// serve serves h at e.DataAddr until the test ends.
func serve(e *gatewaytest.Env, h http.Handler) {
	server := httptest.NewServer(h)
	e.T.Cleanup(server.Close)
	e.DataAddr = server.Listener.Addr().String()
}

// fixedAuthority is a controller whose published generation or blocked
// accounts, when set, a test replaces.
type fixedAuthority struct {
	*controller.Controller
	generation *compile.Generation
	blocked    *store.BlockedAccounts
}

func (a fixedAuthority) Current() *compile.Generation {
	if a.generation != nil {
		return a.generation
	}
	return a.Controller.Current()
}

func (a fixedAuthority) Blocked() *store.BlockedAccounts {
	if a.blocked != nil {
		return a.blocked
	}
	return a.Controller.Blocked()
}

// eventOf returns the last event of the request with the given identifier,
// waiting for want events of it.
func eventOf(e *gatewaytest.Env, requestID string, want int) map[string]any {
	e.T.Helper()
	events := e.RequestEvents(requestID, want)
	if len(events) != want {
		e.T.Fatalf("request %s has %d events, want %d: %v", requestID, len(events), want, events)
	}
	return events[want-1]
}

// admittedStages is the stage map of a forwarded request to an operation
// without a rate rule, body or header schema.
func admittedStages(forward string) map[string]any {
	stages := gatewaytest.ExpectedStages([]string{"INGRESS", "CAPTURE", "CANONICAL", "ROUTE", "ACCESS", "JWT", "RBAC", "BODY", "AUDIT", "BIND"}, "FORWARD", forward)
	stages["RATE"] = audit.StageNotApplicable
	stages["VALIDATION"] = audit.StageNotApplicable
	return stages
}

// The handler needs a controller and a forwarder.
func TestNewHandlerRefusesIncompleteSetup(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	c, _ := own(e, controllerConfig(e))
	forward := (&memoryForwarder{}).forward
	if h, err := newHandler(nil, nil, 0, forward); h != nil || err == nil {
		t.Fatalf("without a controller: %v, %v", h, err)
	}
	if h, err := newHandler(c, pipeline.NewLimiter(), 0, nil); h != nil || err == nil {
		t.Fatalf("without a forwarder: %v, %v", h, err)
	}
	if h, err := newHandler(c, pipeline.NewLimiter(), 0, forward); h == nil || err != nil {
		t.Fatalf("complete setup: %v, %v", h, err)
	}
}

// Under a plain net/http server an admitted request reaches the forwarder
// once, with the trusted binding of its captured generation, the gateway's
// own metadata and no credential, after a durable admission record; no real
// upstream is contacted.
func TestEnforcementHandlerAdmits(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	c, _, f := serveEnforcement(e, e.ProtectedPolicy(), 0)
	g := c.Current()
	admittedFirst := false
	f.setRespond(func(w http.ResponseWriter, r *http.Request) error {
		// The admission record is durable before the forwarder runs.
		id := r.Header.Get("X-Request-Id")
		for _, ev := range e.AuditEvents() {
			admittedFirst = admittedFirst || (ev["kind"] == "request.admitted" && ev["request_id"] == id)
		}
		w.Header().Set("X-Upstream", "memory")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "created")
		return nil
	})

	token := gatewaytest.Issuer.TokenFor(t, "alice")
	resp, body := e.Exchange(http.MethodGet, "/a/x?q=1", "", "", "Authorization", "Bearer "+token,
		"X-Request-Id", "forged", "X-Gateway-Subject", "admin", "X-Gateway-Roles", "ADMIN")
	if resp.StatusCode != http.StatusCreated || body != "created" || resp.Header.Get("X-Upstream") != "memory" {
		t.Fatalf("admitted request: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	got := f.handed()
	if len(got) != 1 {
		t.Fatalf("%d requests handed on, want 1", len(got))
	}
	h := got[0]
	switch {
	case !h.bound || h.dial != e.A.Addr:
		t.Fatalf("binding %v %q, want %q", h.bound, h.dial, e.A.Addr)
	case h.method != http.MethodGet || h.target != "/a/x?q=1":
		t.Fatalf("handed %s %s", h.method, h.target)
	case h.header.Get("X-Gateway-Generation") != g.ID:
		t.Fatalf("generation %q, want %q", h.header.Get("X-Gateway-Generation"), g.ID)
	case h.header.Get("X-Gateway-Subject") != "alice" || h.header.Get("X-Gateway-Roles") != "WRITER":
		t.Fatalf("identity headers %v", h.header)
	case h.header.Get("X-Request-Id") == "" || h.header.Get("X-Request-Id") == "forged":
		t.Fatalf("request identifier %q", h.header.Get("X-Request-Id"))
	case h.header.Get("Authorization") != "":
		t.Fatal("the credential was handed on")
	case !admittedFirst:
		t.Fatal("the admission record was not durable before forwarding")
	}
	ev := eventOf(e, h.header.Get("X-Request-Id"), 2)
	if ev["kind"] != "request.forwarded" || ev["decision"] != "forwarded" || ev["status"] != float64(201) ||
		ev["generation"] != g.ID || ev["upstream"] != "A" || ev["subject"] != "alice" ||
		!gatewaytest.SameStages(ev["stages"], admittedStages(audit.StagePass)) {
		t.Fatalf("outcome event %v", ev)
	}
	if audit := e.AuditEvents(); strings.Contains(fmt.Sprint(audit), token[:40]) || strings.Contains(fmt.Sprint(audit), "q=1") {
		t.Fatal("the audit log holds the token or the query")
	}
	e.AssertReceipts(0, 0, 0)
}

// When the audit log cannot durably record an admission, nothing is
// forwarded: the request is refused at the AUDIT stage, after every other
// stage passed, and the refusal it cannot record is counted as lost.
func TestEnforcementAuditFailureBlocksForwarding(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	c, _, f := serveEnforcement(e, e.ProtectedPolicy(), 0)
	if code, _ := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice")); code != http.StatusOK {
		t.Fatalf("before the failure: %d", code)
	}
	// The state a failed write or sync leaves the log in.
	c.Audit().Fail(errors.New("injected write failure"))
	lost := c.Audit().Lost()
	code, body := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice"))
	var reply struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}
	json.Unmarshal([]byte(body), &reply)
	if code != http.StatusServiceUnavailable || reply.Error != "gateway_unavailable" || reply.RequestID == "" {
		t.Fatalf("with a failed audit log: %d %s", code, body)
	}
	if n := len(f.handed()); n != 1 {
		t.Fatalf("%d requests handed on, want 1", n)
	}
	if got := c.Audit().Lost(); got != lost+1 {
		t.Fatalf("lost events %d, want %d", got, lost+1)
	}
	// A refusal before the AUDIT stage needs no acknowledgement and is
	// answered as before.
	if code, _ := e.Get("/a/x"); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated with a failed audit log: %d", code)
	}
	e.AssertReceipts(0, 0, 0)
}
