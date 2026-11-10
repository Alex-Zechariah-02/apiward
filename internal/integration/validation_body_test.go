// Body ceiling on actual bytes.

package integration

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// bodyFramings are the request framings the data plane serves for a body:
// HTTP/1.1 with a declared length or chunked.
var bodyFramings = []string{"declared", "chunked"}

// The effective body ceiling is the smaller of the global ceiling (16384
// bytes in the test configuration) and the operation's own, and it bounds the
// bytes actually read whatever the framing: a declared length or a chunked
// body. A body of exactly the ceiling reaches the upstream whole, with a
// declared length; one byte more is refused with 413 and reaches no upstream.
func TestBodyCeilingAppliesToActualBytes(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.Policy(e.A, false)
	p.Operations = append(p.Operations,
		policy.Operation{ID: "large", API: "a", Method: "POST", Target: "/a/large", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(32768, gatewaytest.AnyObject)},
		policy.Operation{ID: "small", API: "a", Method: "POST", Target: "/a/small", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(8192, gatewaytest.AnyObject)},
		policy.Operation{ID: "equal", API: "a", Method: "POST", Target: "/a/equal", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(16384, gatewaytest.AnyObject)},
	)
	gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
	e.Interruptible = true
	e.Start(gatewaytest.Binaries.Plain)
	const global = 16384
	var ingressIDs []string
	routed := []string{"INGRESS", "CAPTURE", "CANONICAL", "ROUTE", "ACCESS"}

	operations := []struct {
		name, path string
		ceiling    int
	}{
		{"global below the operation", "/a/large", global},
		{"operation below the global", "/a/small", 8192},
		{"equal ceilings", "/a/equal", global},
	}
	forwarded := 0
	for _, op := range operations {
		for _, framing := range bodyFramings {
			for _, size := range []int{op.ceiling, op.ceiling + 1} {
				name := fmt.Sprintf("%s, %s, %d bytes", op.name, framing, size)
				body := gatewaytest.SizedBody("", size)
				status, reply := e.SendBody(framing, op.path, body)
				if size == op.ceiling {
					forwarded++
					receipts := e.A.Receipts()
					if status != http.StatusOK || len(receipts) != forwarded {
						t.Fatalf("%s: status %d (%s), %d receipts, want 200 and %d", name, status, reply, len(receipts), forwarded)
					}
					last := receipts[forwarded-1]
					if last.Body != body || last.Headers.Get("Content-Length") != strconv.Itoa(size) || len(last.Trailer) != 0 {
						t.Errorf("%s: upstream received %d bytes (intact %v) with Content-Length %q",
							name, len(last.Body), last.Body == body, last.Headers.Get("Content-Length"))
					}
					continue
				}

				stage, reason := gatewaytest.SizeRefusal(framing, size, global)
				want := gatewaytest.Public(gatewaytest.ExpectedStages(routed, "BODY", audit.StageReject))
				_, id := gatewaytest.RequestID(&http.Response{StatusCode: status}, reply)
				if stage == "INGRESS" {
					ingressIDs = append(ingressIDs, id)
					if status != http.StatusRequestEntityTooLarge {
						t.Errorf("%s: status %d (%s), want 413 at INGRESS", name, status, reply)
					}
				} else if events := e.RequestEvents(id, 1); status != http.StatusRequestEntityTooLarge || len(events) != 1 || events[0]["kind"] != "request.rejected" ||
					events[0]["stage"] != stage || events[0]["status"] != float64(413) || events[0]["error"] != "payload_too_large" ||
					!gatewaytest.SameStages(events[0]["stages"], want) {
					t.Errorf("%s: status %d (%s), events %v, want 413 at %s", name, status, reply, events, stage)
				} else if got, _ := events[0]["reason"].(string); got != reason {
					t.Errorf("%s: reason %q, want %q", name, got, reason)
				}
				if n := e.A.Count(); n != forwarded {
					t.Fatalf("%s: %d receipts, want %d: a refused body was forwarded", name, n, forwarded)
				}
			}
		}
	}

	// A chunked body that announces more than the ceiling and stalls one byte
	// past it is refused at once: the read stops at the ceiling instead of
	// waiting for the rest, and the connection is closed.
	conn, err := net.DialTimeout("tcp", e.DataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	started := time.Now()
	io.WriteString(conn, "POST /a/large HTTP/1.1\r\nHost: gw\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"+
		fmt.Sprintf("%x\r\n", 20000)+gatewaytest.SizedBody("", 20000)[:global+1])
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("stalled chunked body: %v", err)
	}
	resp.Body.Close()
	if elapsed := time.Since(started); resp.StatusCode != http.StatusRequestEntityTooLarge || !resp.Close || elapsed > 5*time.Second {
		t.Errorf("stalled chunked body: %d after %v, connection closed %v; want 413 at once with the connection closed", resp.StatusCode, elapsed, resp.Close)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("stalled chunked body: the gateway kept the connection open after its 413 (%v)", err)
	}
	conn.Close()

	// Framing as the HTTP server reads it: an invalid chunk fails the read; a
	// chunked body overrides a declared length (RFC 9112 section 6.3), so a
	// small declared length cannot hide a large body; and an HTTP/1.0 request
	// has no chunked framing, so its body is empty. None is forwarded.
	head := "POST /a/large HTTP/1.1\r\nHost: gw\r\nConnection: close\r\nContent-Type: application/json\r\n"
	framingCases := []struct {
		name, request string
		status        int
		reason        string
	}{
		{"invalid chunk size", head + "Transfer-Encoding: chunked\r\n\r\nzz\r\n{}\r\n0\r\n\r\n", 400, "read_failed"},
		{"declared length with a chunked body above the ceiling",
			head + "Content-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n" + gatewaytest.ChunkedBody(gatewaytest.SizedBody("", global+1), 4096), 413, "too_large"},
		{"HTTP/1.0 chunked body above the ceiling", strings.Replace(head, "HTTP/1.1", "HTTP/1.0", 1) +
			"Transfer-Encoding: chunked\r\n\r\n" + gatewaytest.ChunkedBody(gatewaytest.SizedBody("", global+1), 4096), 400, "malformed_json"},
	}
	for _, tc := range framingCases {
		status, reply := e.RawExchange(tc.request, false)
		_, id := gatewaytest.RequestID(&http.Response{StatusCode: status}, reply)
		events := e.RequestEvents(id, 1)
		if status != tc.status || len(events) != 1 || events[0]["stage"] != "BODY" || events[0]["reason"] != tc.reason {
			t.Errorf("%s: status %d (%s), events %v, want %d with reason %s", tc.name, status, reply, events, tc.status, tc.reason)
		}
	}
	if n := e.A.Count(); n != forwarded {
		t.Fatalf("%d receipts after the framing cases, want %d", n, forwarded)
	}

	// Concurrent chunked requests at and one byte above the ceiling, whose
	// length is known only as they are read: each accepted body arrives once
	// and intact, and no refused body arrives.
	e.ResetReceivers()
	var mu sync.Mutex
	var accepted []string
	var wg sync.WaitGroup
	for client := range 8 {
		wg.Go(func() {
			for i := range 8 {
				size := global + i%2
				body := gatewaytest.SizedBody(fmt.Sprintf("c%d-%d-", client, i), size)
				status, reply := e.SendBody("chunked", "/a/large", body)
				want := http.StatusOK
				if size > global {
					want = http.StatusRequestEntityTooLarge
				}
				if status != want {
					t.Errorf("concurrent chunked %d bytes: status %d (%s), want %d", size, status, reply, want)
				}
				if status == http.StatusOK {
					mu.Lock()
					accepted = append(accepted, body)
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	var received []string
	for _, r := range e.A.Receipts() {
		received = append(received, r.Body)
	}
	slices.Sort(accepted)
	slices.Sort(received)
	if len(accepted) != 32 || !slices.Equal(received, accepted) {
		t.Fatalf("concurrent: %d accepted, %d received, equal %v", len(accepted), len(received), slices.Equal(received, accepted))
	}
	e.AssertReceipts(32, 0, 0)
	// Declared lengths above the global ceiling are counted at ingress.
	if got := e.IngressSummary(); got["too_large"] != len(ingressIDs) || len(got) != 1 || len(ingressIDs) != 2 {
		t.Errorf("ingress summary %v for %d declared refusals, want 2 too_large", got, len(ingressIDs))
	}
	if ev := gatewaytest.RecordOf(e.AuditEvents(), ingressIDs); ev != nil {
		t.Errorf("ingress refusal recorded on its own: %v", ev)
	}
}
