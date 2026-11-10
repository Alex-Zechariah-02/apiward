// Forwarding helpers, setup, fixtures and bound destinations.

package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// These tests serve the enforcement handler with the native reverse proxy as
// its forwarder, under a plain net/http server in the test process, and
// forward to real loopback upstreams: the deployment's receivers, the three
// fixture processes, or a receiver whose handler stages a failure. What an
// upstream received, or that it received nothing, is read from the upstream
// itself.

// forwardTimeouts are the legacy dial and response-header bounds and the
// read-idle bound of the native transport.
var forwardTimeouts = forward.UpstreamTimeouts{Dial: 2 * time.Second, ResponseHeader: 5 * time.Second, ReadIdle: 5 * time.Second}

// serveNative seeds e's database with policy, owns and starts its controller,
// and serves the enforcement handler with the native proxy, bounded by
// timeouts, at e.DataAddr, where the harness request helpers send. It returns
// the controller and the proxy's log.
func serveNative(e *gatewaytest.Env, policy policy.Policy, timeouts forward.UpstreamTimeouts) (*controller.Controller, *gatewaytest.LogBuffer) {
	e.T.Helper()
	gatewaytest.Seed(e.T, e.Database, policy, gatewaytest.SeedOptions{})
	c, _ := own(e, controllerConfig(e))
	if err := c.Start(testAdmin(c)); err != nil {
		e.T.Fatal(err)
	}
	logs := &gatewaytest.LogBuffer{}
	p, err := forward.NewUpstreamProxy(timeouts, forward.PoolSettings{MaxIdle: 16, IdleTimeout: 30 * time.Second}, c.Network, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		e.T.Fatal(err)
	}
	h, err := newHandler(c, pipeline.NewLimiter(), 0, p.Forward)
	if err != nil {
		e.T.Fatal(err)
	}
	// As in production, "OPTIONS *" reaches enforcement instead of net/http.
	server := httptest.NewUnstartedServer(h)
	server.Config.DisableGeneralOptionsHandler = true
	server.Start()
	e.T.Cleanup(server.Close)
	e.DataAddr = server.Listener.Addr().String()
	return c, logs
}

// fetch sends one GET from a goroutine other than the test's own, reporting
// failures instead of ending the test.
func fetch(addr, path string) (int, string, error) {
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 30 * time.Second}
	resp, err := client.Get("http://" + addr + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), err
}

// outcomeOf returns the outcome event of an admitted request.
func outcomeOf(e *gatewaytest.Env, requestID string) map[string]any {
	e.T.Helper()
	return eventOf(e, requestID, 2)
}

// failedOutcome reports whether ev records a forwarding failure answered
// with status and code, with the given delivery reason.
func failedOutcome(ev map[string]any, status int, code, reason string) bool {
	got, _ := ev["reason"].(string)
	return ev["kind"] == "request.forwarded" && ev["decision"] == "upstream_failure" &&
		ev["status"] == float64(status) && ev["error"] == code && got == reason
}

// Every catalogue step runs through the native proxy against the three
// fixture processes: each admitted request reaches exactly its fixture, which
// runs the intended operation with the expected outcome and state change and
// sees the gateway's identity headers, and every step the gateway refuses
// reaches no fixture.
func TestNativeForwardingThroughFixtures(t *testing.T) {
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	serveNative(e, gatewaytest.FixturePolicy(fixtures), forwardTimeouts)
	c := gatewaytest.LoadCatalogue(t)

	results := gatewaytest.RunScenarios(t, e, fixtures, c)
	if len(results) != len(c.Scenarios) {
		t.Fatalf("%d of %d steps ran", len(results), len(c.Scenarios))
	}
	ran := map[string]bool{}
	for _, r := range results {
		ran[r.Operation] = true
	}
	for _, op := range c.Operations {
		if !ran[op.ID] {
			t.Errorf("catalogue operation %s was never exercised", op.ID)
		}
	}
	e.AssertReceipts(0, 0, 0)
}

// The destination is the binding the handler made from the captured
// generation and nothing else. No client field moves a request; the inbound
// Host reaches the upstream but chooses nothing. A request whose binding is
// missing, forged or not a literal loopback address is sent nowhere: no
// fallback destination exists.
func TestNativeForwardingBinding(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	serveNative(e, e.Policy(e.A, true), forwardTimeouts)

	// Every field a client could use to name a destination names C.
	forged := "Host: " + e.C.Addr + "\r\nX-Forwarded-Host: " + e.C.Addr + "\r\nForwarded: host=" + e.C.Addr +
		"\r\nX-Gateway-Upstream: C\r\nX-Gateway-Dial: " + e.C.Addr + "\r\nConnection: close\r\n\r\n"
	for _, target := range []string{"/a/x", "/a/x?upstream=C&dial=" + e.C.Addr, "/a/" + e.C.Addr} {
		if code, body := e.Raw("GET " + target + " HTTP/1.1\r\n" + forged); code != http.StatusOK || body != "A ok" {
			t.Errorf("%s with forged destination fields: %d %q", target, code, body)
		}
	}
	if code, body := e.Raw("GET /b/x HTTP/1.1\r\nHost: " + e.A.Addr + "\r\nConnection: close\r\n\r\n"); code != http.StatusOK || body != "B ok" {
		t.Errorf("/b/x with a Host naming A: %d %q", code, body)
	}
	if code, _ := e.Raw("GET http://" + e.C.Addr + "/a/x HTTP/1.1\r\nHost: " + e.C.Addr + "\r\nConnection: close\r\n\r\n"); code != http.StatusBadRequest {
		t.Errorf("absolute-form target naming C: %d", code)
	}
	e.AssertReceipts(3, 1, 0)
	for _, r := range e.A.Receipts() {
		if r.Host != e.C.Addr || r.Headers.Get("X-Gateway-Upstream") != "" || r.Headers.Get("X-Gateway-Dial") != "" ||
			r.Headers.Get("Forwarded") != "" || r.Headers.Get("X-Forwarded-Host") != e.C.Addr {
			t.Errorf("A received Host %q and headers %v", r.Host, r.Headers)
		}
	}
}

// A request keeps the destination of the generation it captured while
// another generation is published during its exchange; the next request
// uses the new one.
func TestNativeForwardingKeepsCapturedDestination(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	c, _ := serveNative(e, e.Policy(e.A, false), forwardTimeouts)
	captured := c.Current().ID
	entered, release := make(chan struct{}), make(chan struct{})
	e.A.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/a/slow" {
			close(entered)
			<-release
		}
		return false
	}
	type result struct {
		code int
		body string
		err  error
	}
	slow := make(chan result, 1)
	go func() {
		code, body, err := fetch(e.DataAddr, "/a/slow")
		slow <- result{code, body, err}
	}()
	<-entered
	outcome, status := c.Publish(context.Background(), "test", controller.Change{ID: "move-a", Expected: 1, Policy: gatewaytest.MustJSON(e.Policy(e.B, false))})
	close(release)
	if status != http.StatusOK {
		t.Fatalf("publication during the exchange: %d %+v", status, outcome)
	}
	if r := <-slow; r.err != nil || r.code != http.StatusOK || r.body != "A ok" {
		t.Fatalf("request in progress during the publication: %d %q %v", r.code, r.body, r.err)
	}
	if code, body := e.Get("/a/x"); code != http.StatusOK || body != "B ok" {
		t.Fatalf("request after the publication: %d %q", code, body)
	}
	e.AssertReceipts(1, 1, 0)
	if a, b := e.A.Receipts()[0], e.B.Receipts()[0]; a.Generation != captured || b.Generation != outcome.Generation {
		t.Fatalf("A received generation %s (want %s), B %s (want %s)", a.Generation, captured, b.Generation, outcome.Generation)
	}
}
