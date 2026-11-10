// Proxy setup, and the bindings the proxy refuses to forward.

package forward

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// bounds are the dial, response-header and read-idle limits used here.
var bounds = UpstreamTimeouts{Dial: 2 * time.Second, ResponseHeader: 5 * time.Second, ReadIdle: 5 * time.Second}

// testPool is the default pool, so these tests send through it.
var testPool = PoolSettings{MaxIdle: 16, IdleTimeout: 30 * time.Second}

// closed is the operator default: no public addresses, no TLS profiles.
func closed() *Network {
	n, err := LoadNetwork(false, nil, 0)
	if err != nil {
		panic(err)
	}
	return n
}

// The proxy needs a bound for every phase of an exchange, since a zero would
// leave that phase unbounded, and a logger.
func TestNativeForwardingProxyRefusesIncompleteSetup(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	for name, timeouts := range map[string]UpstreamTimeouts{
		"no dial bound":            {ResponseHeader: time.Second, ReadIdle: time.Second},
		"no response-header bound": {Dial: time.Second, ReadIdle: time.Second},
		"no read-idle bound":       {Dial: time.Second, ResponseHeader: time.Second},
		"negative read-idle bound": {Dial: time.Second, ResponseHeader: time.Second, ReadIdle: -time.Second},
	} {
		if p, err := NewUpstreamProxy(timeouts, testPool, closed, logger); p != nil || err == nil {
			t.Errorf("%s: %v, %v", name, p, err)
		}
	}
	if p, err := NewUpstreamProxy(bounds, testPool, closed, nil); p != nil || err == nil {
		t.Errorf("without a logger: %v, %v", p, err)
	}
	if p, err := NewUpstreamProxy(bounds, testPool, nil, logger); p != nil || err == nil {
		t.Errorf("without network settings: %v, %v", p, err)
	}
	p, err := NewUpstreamProxy(bounds, testPool, closed, logger)
	if err != nil {
		t.Fatal(err)
	}
	if tr := p.transport; tr.Proxy != nil || !tr.DisableKeepAlives || !tr.DisableCompression || tr.ResponseHeaderTimeout != bounds.ResponseHeader ||
		!tr.Protocols.HTTP1() || tr.Protocols.HTTP2() || tr.Protocols.UnencryptedHTTP2() {
		t.Fatalf("transport %+v", tr)
	}
}

// A request whose binding is missing or forged is sent nowhere, whatever
// else it carries: the loopback upstream it names receives nothing. A binding
// holds only a compiled destination, so a host name, an address off loopback
// or one without a port cannot reach the proxy: the compiler refuses them.
func TestUnusableBindingSendsNothing(t *testing.T) {
	var received atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	t.Cleanup(upstream.Close)
	addr := upstream.Listener.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewUpstreamProxy(bounds, testPool, closed, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	type otherKey struct{}
	unusable := []struct {
		name  string
		value func(context.Context) context.Context
	}{
		{"no binding", func(ctx context.Context) context.Context { return ctx }},
		{"binding under another key", func(ctx context.Context) context.Context {
			return context.WithValue(ctx, otherKey{}, addr)
		}},
		{"destination as a plain value", func(ctx context.Context) context.Context { return context.WithValue(ctx, bindingKey{}, addr) }},
		{"empty binding", func(ctx context.Context) context.Context { return context.WithValue(ctx, bindingKey{}, binding{}) }},
	}
	for _, tc := range unusable {
		r := httptest.NewRequest(http.MethodGet, "/a/x", nil)
		r.Header.Set("X-Gateway-Dial", addr)
		rec := httptest.NewRecorder()
		err := p.Forward(rec, r.WithContext(tc.value(r.Context())))
		status, code := ForwardFailure(err)
		if status != http.StatusServiceUnavailable || code != "gateway_unavailable" || FailureReason(err) != "not_sent" || rec.Body.Len() != 0 || len(rec.Header()) != 0 {
			t.Errorf("%s: %v maps to %d %s (%s), response %d %v", tc.name, err, status, code, FailureReason(err), rec.Code, rec.Header())
		}
	}
	if n := received.Load(); n != 0 {
		t.Fatalf("the upstream received %d requests", n)
	}
	for _, dial := range []string{"localhost:" + port, "192.0.2.1:80", "127.0.0.1"} {
		p := policy.Policy{SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore, Upstreams: []policy.Upstream{{ID: "u", Dial: dial}}}
		if g, err := compile.Compile(p, 1, time.Time{}); g != nil || err == nil {
			t.Errorf("dial %q compiled", dial)
		}
	}
}
