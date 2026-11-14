// Overload caps: requests past data.max_in_flight are refused at INGRESS
// with Retry-After and recorded, and connections past data.max_connections
// are closed before any byte and counted.

package gateway

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/connections"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

func TestInFlightCapRefuses(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	c, _, f := serveEnforcement(e, e.Policy(e.A, true), pipeline.Limits{MaxInFlight: 1})
	held, proceed := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(proceed) })
	t.Cleanup(release)
	f.setRespond(func(w http.ResponseWriter, r *http.Request) error {
		if r.URL.Path == "/a/held" {
			close(held)
			<-proceed
		}
		io.WriteString(w, "forwarded")
		return nil
	})
	conn, err := net.Dial("tcp", e.DataAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /a/held HTTP/1.1\r\nHost: gw\r\n\r\n")
	<-held

	resp, body := e.Exchange(http.MethodGet, "/a/x", "", "")
	_, refused := gatewaytest.RequestID(resp, body)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" || !strings.Contains(body, "overloaded") {
		t.Fatalf("second request at the cap: %d Retry-After %q, %s", resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
	release()
	// The next request goes on the held request's own connection: the server
	// reads it only after that handler returned, which is when its place is
	// free. A new connection could be served before then.
	reader := bufio.NewReader(conn)
	for _, step := range []string{"the held request", "the request after it"} {
		if step != "the held request" {
			io.WriteString(conn, "GET /a/x HTTP/1.1\r\nHost: gw\r\n\r\n")
		}
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", step, resp.StatusCode, body)
		}
	}
	checkIngressSummary(t, e, c, map[string]int{"overloaded": 1}, []string{refused})
}

func TestConnectionCapClosesExtra(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := make(chan struct{}, 4)
	l := connections.Cap(inner, 1, func() { refused <- struct{}{} })
	defer l.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	dial := func() net.Conn {
		conn, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	dial()
	first := <-accepted
	extra := dial()
	<-refused
	extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := extra.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("connection past the cap: read %d, %v; want closed", n, err)
	}
	first.Close()
	dial()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("a connection after one closed was not accepted")
	}
}
