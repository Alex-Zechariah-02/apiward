// The upstream connection pool and TLS session resumption: connections are
// reused, a request that fails on a reused connection is never sent again,
// a connection the upstream closed while idle is not used, and sessions are
// resumed only within their lifetime and never across a reload.

package forward

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// forwarder returns a function that forwards GET /x to u through one proxy
// with pool settings and network n, giving the failure reason ("" when
// forwarded).
func forwarder(t *testing.T, n *Network, pool PoolSettings, u policy.Upstream) (*upstreamProxy, func() string) {
	t.Helper()
	proxy, err := NewUpstreamProxy(bounds, pool, func() *Network { return n }, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Close)
	d := destination(t, u)
	return proxy, func() string {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		if err := proxy.Forward(rec, r.WithContext(Bind(context.Background(), d))); err != nil {
			return FailureReason(err)
		}
		return ""
	}
}

// waitIdle waits until the pool holds want idle connections.
func waitIdle(t *testing.T, p *connPool, want int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		p.mu.Lock()
		n := 0
		for _, list := range p.idle {
			n += len(list)
		}
		p.mu.Unlock()
		if n == want {
			return
		}
	}
	t.Fatalf("the pool never held %d idle connections", want)
}

// Two requests share one connection; when the upstream closes it while
// idle, the next request opens a new one instead of failing on it.
func TestPoolReusesLiveConnections(t *testing.T) {
	var conns atomic.Int64
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	s.Start()
	t.Cleanup(s.Close)
	proxy, send := forwarder(t, closed(), testPool, policy.Upstream{ID: "u", Dial: s.Listener.Addr().String()})
	if send() != "" || send() != "" || conns.Load() != 1 {
		t.Fatalf("two requests used %d connections, want 1", conns.Load())
	}
	waitIdle(t, proxy.pool, 1)
	s.CloseClientConnections()
	waitIdle(t, proxy.pool, 0)
	if reason := send(); reason != "" || conns.Load() != 2 {
		t.Fatalf("after the upstream closed the idle connection: %q, %d connections", reason, conns.Load())
	}
}

// A request that fails on a reused connection after it was written is
// reported as maybe delivered and never sent again, though GET is a method
// the standard transport would resend.
func TestPoolNeverResends(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var accepted, requests atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				// Answers the first request and closes after reading the
				// second without answering it.
				for i := 0; ; i++ {
					if _, err := http.ReadRequest(reader); err != nil {
						return
					}
					requests.Add(1)
					if i == 1 {
						return
					}
					conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				}
			}()
		}
	}()
	proxy, send := forwarder(t, closed(), testPool, policy.Upstream{ID: "u", Dial: listener.Addr().String()})
	if reason := send(); reason != "" {
		t.Fatalf("first request: %q", reason)
	}
	waitIdle(t, proxy.pool, 1)
	if reason := send(); reason != "outcome_unknown" {
		t.Fatalf("request failing on a reused connection: %q, want outcome_unknown", reason)
	}
	time.Sleep(100 * time.Millisecond) // time for a resend to arrive, if one were made
	if accepted.Load() != 1 || requests.Load() != 2 {
		t.Fatalf("%d connections and %d requests reached the upstream, want 1 and 2", accepted.Load(), requests.Load())
	}
}

// A TLS session is resumed on the next connection within its lifetime, but
// not after the lifetime, and not by a reloaded network.
func TestSessionResumption(t *testing.T) {
	dir, ca := t.TempDir(), newIssuer(t)
	_, _, serverPair := ca.leaf(t, dir, "server", false, []net.IP{net.IPv4(127, 0, 0, 1)})
	clientCert, clientKey, _ := ca.leaf(t, dir, "gateway", true, nil)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	resumed := make(chan bool, 4)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resumed <- r.TLS.DidResume
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	s.StartTLS()
	t.Cleanup(s.Close)
	u := policy.Upstream{ID: "u", URL: "https://" + s.Listener.Addr().String(), TLS: "full"}
	load := func(lifetime time.Duration) *Network {
		n, err := LoadNetwork(false, []ProfileSettings{{ID: "full", CAFile: ca.file(t, dir), ClientCertificateFile: clientCert, ClientKeyFile: clientKey}}, lifetime)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	noPool := PoolSettings{}
	for _, step := range []struct {
		name    string
		network *Network
		want    []bool
	}{
		{"within the lifetime", load(time.Hour), []bool{false, true}},
		{"after the lifetime", load(time.Nanosecond), []bool{false, false}},
		{"after a reload", load(time.Hour), []bool{false}},
	} {
		_, send := forwarder(t, step.network, noPool, u)
		for i, want := range step.want {
			if reason := send(); reason != "" {
				t.Fatalf("%s: %q", step.name, reason)
			}
			if got := <-resumed; got != want {
				t.Fatalf("%s: connection %d resumed %v, want %v", step.name, i+1, got, want)
			}
		}
	}
}
