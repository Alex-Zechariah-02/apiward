// Slow upstreams: one that accepts a connection and stops taking the request
// must end the exchange within its bounds, and a response that arrives slowly
// must reach the client as it arrives.

package forward

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestUpstreamThatStopsReadingTimesOut(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	held := make(chan net.Conn, 1)
	go func() {
		if conn, err := listener.Accept(); err == nil {
			held <- conn // kept open and never read
		}
	}()
	t.Cleanup(func() {
		select {
		case conn := <-held:
			conn.Close()
		default:
		}
	})

	d := destination(t, policy.Upstream{ID: "u", Dial: listener.Addr().String()}, http.MethodPost)
	short := UpstreamTimeouts{Dial: time.Second, ResponseHeader: 300 * time.Millisecond, ReadIdle: time.Second}
	proxy, err := NewUpstreamProxy(short, testPool, closed, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	// Far more than the socket buffers hold, so the write itself must stall.
	body := bytes.NewReader(make([]byte, 32<<20))
	r := httptest.NewRequest(http.MethodPost, "/x", body)
	done := make(chan error, 1)
	go func() { done <- proxy.Forward(httptest.NewRecorder(), r.WithContext(Bind(context.Background(), d))) }()
	select {
	case err := <-done:
		status, code := ForwardFailure(err)
		if !errors.Is(err, ErrUpstreamTimeout) || status != http.StatusGatewayTimeout || code != "upstream_timeout" || FailureReason(err) != "outcome_unknown" {
			t.Fatalf("%v maps to %d %s (%s)", err, status, code, FailureReason(err))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the exchange is still writing to an upstream that stopped reading")
	}
}

// A response with a declared length whose body arrives slowly reaches the
// client as it arrives: its headers do not wait for the upstream to finish.
func TestSlowResponseStreams(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.Write([]byte("a"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		w.Write([]byte("b"))
	}))
	t.Cleanup(upstream.Close)
	d := destination(t, policy.Upstream{ID: "u", Dial: upstream.Listener.Addr().String()}, http.MethodGet)
	proxy, err := NewUpstreamProxy(UpstreamTimeouts{Dial: time.Second, ResponseHeader: time.Second, ReadIdle: 10 * time.Second}, testPool, closed, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.Forward(w, r.WithContext(Bind(r.Context(), d)))
	}))
	t.Cleanup(front.Close)

	started := time.Now()
	resp, err := http.Get(front.URL + "/x")
	waited := time.Since(started)
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "ab" {
		t.Fatalf("body %q, %v", body, err)
	}
	if waited > 2*time.Second {
		t.Fatalf("headers reached the client after %s, when the upstream finished", waited)
	}
}
