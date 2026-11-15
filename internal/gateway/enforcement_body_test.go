// Request body ceiling, unparsed lengths and connection close on refusals.

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// The effective body ceiling, the smaller of the global and the operation's,
// bounds the bytes read for a declared and for a chunked body: exactly the
// ceiling is handed on whole with its length declared, one byte more is
// refused with 413 and never handed on.
func TestEnforcementBodyCeiling(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	p := e.Policy(e.A, false)
	p.Operations = append(p.Operations,
		policy.Operation{ID: "large", API: "a", Method: "POST", Target: "/a/large", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(4096, gatewaytest.AnyObject)},
		policy.Operation{ID: "small", API: "a", Method: "POST", Target: "/a/small", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(1024, gatewaytest.AnyObject)},
		policy.Operation{ID: "equal", API: "a", Method: "POST", Target: "/a/equal", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(2048, gatewaytest.AnyObject)},
	)
	const global = 2048
	c, _, f := serveEnforcement(e, p, pipeline.Limits{MaxBodyBytes: global})
	routed := []string{"INGRESS", "CAPTURE", "CANONICAL", "ROUTE", "ACCESS"}
	summarised, ingressIDs := map[string]int{}, []string{}
	operations := []struct {
		name, path string
		ceiling    int
	}{
		{"global below the operation", "/a/large", global},
		{"operation below the global", "/a/small", 1024},
		{"equal ceilings", "/a/equal", global},
	}
	handed := 0
	for _, op := range operations {
		for _, framing := range []string{"declared", "chunked"} {
			for _, size := range []int{op.ceiling, op.ceiling + 1} {
				name := fmt.Sprintf("%s, %s, %d bytes", op.name, framing, size)
				body := gatewaytest.SizedBody("", size)
				status, reply := e.SendBody(framing, op.path, body)
				if size == op.ceiling {
					handed++
					got := f.handed()
					if status != http.StatusOK || len(got) != handed {
						t.Fatalf("%s: status %d (%s), %d handed on, want 200 and %d", name, status, reply, len(got), handed)
					}
					last := got[handed-1]
					if last.body != body || last.header.Get("Content-Length") != fmt.Sprint(size) || last.header.Get("Transfer-Encoding") != "" {
						t.Errorf("%s: handed %d bytes (intact %v) with Content-Length %q", name, len(last.body), last.body == body, last.header.Get("Content-Length"))
					}
					continue
				}
				stage, reason := gatewaytest.SizeRefusal(size, global)
				_, id := gatewaytest.RequestID(&http.Response{StatusCode: status}, reply)
				if stage == "INGRESS" {
					summarised[reason]++
					ingressIDs = append(ingressIDs, id)
					if status != http.StatusRequestEntityTooLarge {
						t.Errorf("%s: status %d (%s), want 413 at INGRESS", name, status, reply)
					}
				} else if ev, got := eventReason(e, id); status != http.StatusRequestEntityTooLarge || ev["stage"] != stage || got != reason ||
					ev["error"] != "payload_too_large" || !gatewaytest.SameStages(ev["stages"], gatewaytest.Public(gatewaytest.ExpectedStages(routed, "BODY", audit.StageReject))) {
					t.Errorf("%s: status %d (%s), event %v, want 413 at %s", name, status, reply, ev, stage)
				}
				if n := len(f.handed()); n != handed {
					t.Fatalf("%s: %d handed on, want %d: a refused body was forwarded", name, n, handed)
				}
			}
		}
	}
	e.AssertReceipts(0, 0, 0)
	checkIngressSummary(t, e, c, summarised, ingressIDs)
}

// HTTP/2 reads an unparseable Content-Length as 0 and keeps the stream open
// (net/http/internal/http2 server.go, processHeaders); such a request is
// refused at ingress, as HTTP/1 refuses it, and never reaches an upstream.
func TestUnparsedContentLength(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	_, h, f := serveEnforcement(e, e.Policy(e.A, false), pipeline.Limits{})
	req := httptest.NewRequest(http.MethodGet, "/a/x", strings.NewReader("smuggled"))
	req.ProtoMajor, req.ProtoMinor, req.ContentLength = 2, 0, 0
	req.Header.Set("Content-Length", "abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || len(f.handed()) != 0 {
		t.Fatalf("%d, %d handed on; want 400 at ingress, none handed on", rec.Code, len(f.handed()))
	}
}

// An HTTP/1 request refused before its body is read (here at ingress, for an
// upgrade) closes its connection; an HTTP/2 one does not, since that would end
// every stream on the connection.
func TestRefusalCloseOnlyHTTP1(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	_, h, _ := serveEnforcement(e, e.Policy(e.A, false), pipeline.Limits{})
	for major, want := range map[int]string{1: "close", 2: ""} {
		req := httptest.NewRequest(http.MethodGet, "/a/x", strings.NewReader("unexpected"))
		req.ProtoMajor = major
		req.Header.Set("Upgrade", "websocket")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Connection") != want {
			t.Errorf("HTTP/%d: %d, Connection %q; want 400, %q", major, rec.Code, rec.Header().Get("Connection"), want)
		}
	}
}
