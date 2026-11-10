// An upstream that accepts a connection and stops taking the request: the
// exchange must end within its bounds instead of waiting for the client.

package forward

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
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

	p := policy.Policy{SchemaVersion: policy.LatestSchemaVersion, Profile: policy.ProfileCore,
		Upstreams:  []policy.Upstream{{ID: "u", Dial: listener.Addr().String()}},
		APIs:       []policy.API{{ID: "api", Upstream: "u"}},
		Operations: []policy.Operation{{ID: "op", API: "api", Method: "POST", Target: "/x", Access: "allow", Auth: "none"}}}
	g, err := compile.Compile(p, 1, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	_, rule := g.Match("/x", "POST", compile.Inbound{})
	d, ok := rule.Destination("/x")
	if !ok {
		t.Fatal("no destination")
	}
	short := UpstreamTimeouts{Dial: time.Second, ResponseHeader: 300 * time.Millisecond, ReadIdle: time.Second}
	proxy, err := NewUpstreamProxy(short, closed, slog.New(slog.DiscardHandler))
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
