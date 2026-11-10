// Enforcement refusals, body ceiling and rate limit.

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Every refusal is decided at its stage, answered with its status, error code
// and request identifier, recorded with its reason, and never handed on.
func TestEnforcementRefusals(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.ProtectedPolicy()
	p.Operations = append(p.Operations,
		policy.Operation{ID: "strict", API: "a", Method: "POST", Target: "/a/strict", Access: "allow", Auth: "required",
			Body: gatewaytest.JSONBody(1024, `{"type":"object","additionalProperties":true,"required":["n"],"properties":{"n":{"type":"integer"}}}`)},
		policy.Operation{ID: "probe", API: "a", Method: "GET", Target: "/a/probe", Access: "allow", Auth: "none",
			Headers: json.RawMessage(`{"type":"object","additionalProperties":true,"required":["X-Probe"],"properties":{"X-Probe":{"type":"string","enum":["on"]}}}`)},
	)
	p.Permits = append(p.Permits, policy.Permit{Role: "WRITER", Operation: "strict"})
	gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
	controller, _ := own(e, controllerConfig(e))
	blocked := store.BlockedAccounts{"carol": {Subject: "carol", Reason: "test containment"}}
	f := serveAuthority(e, controller, fixedAuthority{Controller: controller, blocked: &blocked})

	bearer := func(subject string) string { return "Bearer " + gatewaytest.Issuer.TokenFor(t, subject) }
	claims := func(changes map[string]any) string {
		return "Bearer " + gatewaytest.Issuer.Token(t, issuertest.Changed(issuertest.ValidClaims("alice"), changes))
	}
	valid := gatewaytest.Issuer.TokenFor(t, "alice")
	segments := strings.Split(valid, ".")
	tampered := segments[0] + "." + segments[1] + ".AAAA" + segments[2][4:]
	raw := func(request string) string { return request + "Host: gw\r\nConnection: close\r\n\r\n" }

	cases := []struct {
		name    string
		raw     string   // sent byte for byte when set
		method  string   // otherwise the request
		path    string   //
		ctype   string   //
		body    string   //
		header  []string // name/value pairs
		status  int
		code    string
		stage   string
		reason  string
		allowed string // expected Allow header
	}{
		{name: "absolute-form target", raw: raw("GET http://" + e.A.Addr + "/a/x HTTP/1.1\r\n"), status: 400, code: "bad_request", stage: "INGRESS"},
		{name: "tunnel", raw: raw("CONNECT " + e.A.Addr + " HTTP/1.1\r\n"), status: 400, code: "bad_request", stage: "INGRESS"},
		{name: "protocol upgrade", raw: raw("GET /a/x HTTP/1.1\r\nUpgrade: websocket\r\n"), status: 400, code: "bad_request", stage: "INGRESS"},
		{name: "Connection naming a gateway header", raw: raw("GET /a/x HTTP/1.1\r\nConnection: X-Gateway-Subject\r\n"), status: 400, code: "bad_request", stage: "INGRESS"},
		{name: "declared length above the global ceiling", raw: raw("POST /a/item HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 16385\r\n"),
			status: 413, code: "payload_too_large", stage: "INGRESS"},
		{name: "encoded dot segment", raw: raw("GET /a/%2e%2e/x HTTP/1.1\r\n"), status: 400, code: "bad_request", stage: "CANONICAL"},
		{name: "empty segment", raw: raw("GET /a//x HTTP/1.1\r\n"), status: 400, code: "bad_request", stage: "CANONICAL"},
		{name: "unknown target", method: "GET", path: "/zzz", status: 404, code: "not_found", stage: "ROUTE"},
		{name: "method not declared", method: "DELETE", path: "/a/x", status: 405, code: "method_not_allowed", stage: "ROUTE", allowed: "GET"},
		{name: "denied operation", method: "GET", path: "/d", status: 403, code: "forbidden", stage: "ACCESS"},
		{name: "no token", method: "GET", path: "/a/x", status: 401, code: "unauthenticated", stage: "JWT", reason: "missing_credential"},
		{name: "expired token", method: "GET", path: "/a/x", header: []string{"Authorization", claims(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()})},
			status: 401, code: "unauthenticated", stage: "JWT", reason: "expired"},
		{name: "wrong audience", method: "GET", path: "/a/x", header: []string{"Authorization", claims(map[string]any{"aud": "other"})},
			status: 401, code: "unauthenticated", stage: "JWT", reason: "wrong_audience"},
		{name: "signature altered", method: "GET", path: "/a/x", header: []string{"Authorization", "Bearer " + tampered},
			status: 401, code: "unauthenticated", stage: "JWT", reason: "invalid_signature"},
		{name: "unsigned token", method: "GET", path: "/a/x", header: []string{"Authorization", "Bearer " + issuertest.EncodeSegment(`{"alg":"none"}`) + "." + segments[1] + "."},
			status: 401, code: "unauthenticated", stage: "JWT", reason: "malformed_credential"},
		{name: "unknown subject", method: "GET", path: "/a/x", header: []string{"Authorization", bearer("mallory")},
			status: 403, code: "forbidden", stage: "RBAC", reason: "no_permit"},
		{name: "subject without a permit", method: "POST", path: "/a/item", ctype: "application/json", body: `{"n":1}`, header: []string{"Authorization", bearer("bob")},
			status: 403, code: "forbidden", stage: "RBAC", reason: "no_permit"},
		{name: "unknown role claimed in the verified token", method: "POST", path: "/a/item", ctype: "application/json", body: `{"n":1}`,
			header: []string{"Authorization", "Bearer " + gatewaytest.Issuer.Token(t, issuertest.Changed(issuertest.ValidClaims("bob"), map[string]any{"roles": []string{"ADMIN"}}))},
			status: 403, code: "forbidden", stage: "RBAC", reason: "no_permit"},
		{name: "disabled subject", method: "GET", path: "/a/x", header: []string{"Authorization", bearer("carol")},
			status: 403, code: "account_blocked", stage: "RBAC", reason: "account_blocked"},
		{name: "body where none is declared", method: "GET", path: "/a/x", body: "x", header: []string{"Authorization", bearer("alice")},
			status: 400, code: "bad_request", stage: "BODY", reason: "unexpected_body"},
		{name: "media type", method: "POST", path: "/a/item", ctype: "text/plain", body: `{"n":1}`, header: []string{"Authorization", bearer("alice")},
			status: 415, code: "unsupported_media_type", stage: "BODY", reason: "media_type"},
		{name: "malformed JSON", method: "POST", path: "/a/item", ctype: "application/json", body: `{"n":`, header: []string{"Authorization", bearer("alice")},
			status: 400, code: "bad_request", stage: "BODY", reason: "malformed_json"},
		{name: "body schema", method: "POST", path: "/a/strict", ctype: "application/json", body: `{"n":"one"}`, header: []string{"Authorization", bearer("alice")},
			status: 400, code: "bad_request", stage: "VALIDATION", reason: "schema_mismatch"},
		{name: "required header missing", method: "GET", path: "/a/probe", status: 400, code: "bad_request", stage: "VALIDATION", reason: "header_mismatch"},
		{name: "header value outside its schema", method: "GET", path: "/a/probe", header: []string{"X-Probe", "off"},
			status: 400, code: "bad_request", stage: "VALIDATION", reason: "header_mismatch"},
		{name: "repeated header", raw: raw("GET /a/probe HTTP/1.1\r\nX-Probe: on\r\nX-Probe: on\r\n"),
			status: 400, code: "bad_request", stage: "VALIDATION", reason: "repeated_header"},
	}
	for _, tc := range cases {
		var resp *http.Response
		var body string
		if tc.raw != "" {
			resp, body = e.RawResponse(tc.raw)
		} else {
			resp, body = e.Exchange(tc.method, tc.path, tc.ctype, tc.body, tc.header...)
		}
		var reply struct {
			Error     string `json:"error"`
			RequestID string `json:"request_id"`
		}
		json.Unmarshal([]byte(body), &reply)
		if resp.StatusCode != tc.status || reply.Error != tc.code || reply.RequestID == "" {
			t.Errorf("%s: %d %s, want %d %s", tc.name, resp.StatusCode, body, tc.status, tc.code)
			continue
		}
		if tc.allowed != "" && !strings.Contains(resp.Header.Get("Allow"), tc.allowed) {
			t.Errorf("%s: Allow %q", tc.name, resp.Header.Get("Allow"))
		}
		if tc.stage == "JWT" && resp.Header.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: WWW-Authenticate %q", tc.name, resp.Header.Get("WWW-Authenticate"))
		}
		ev := eventOf(e, reply.RequestID, 1)
		reason, _ := ev["reason"].(string)
		if ev["kind"] != "request.rejected" || ev["stage"] != tc.stage || ev["error"] != tc.code ||
			ev["status"] != float64(tc.status) || ev["decision"] != "reject" || reason != tc.reason {
			t.Errorf("%s: event %v, want %s at %s (%q)", tc.name, ev, tc.code, tc.stage, tc.reason)
		}
		if n := len(f.handed()); n != 0 {
			t.Fatalf("%s: %d requests handed on", tc.name, n)
		}
	}

	// The same operations admit valid requests.
	if code, _ := e.Request(http.MethodPost, "/a/strict", "application/json", `{"n":1}`, "Authorization", bearer("alice")); code != http.StatusOK {
		t.Fatalf("valid body: %d", code)
	}
	if code, _ := e.Get("/a/probe", "X-Probe", "on"); code != http.StatusOK {
		t.Fatalf("valid header: %d", code)
	}
	got := f.handed()
	if len(got) != 2 || got[0].body != `{"n":1}` || got[1].header.Get("X-Probe") != "on" {
		t.Fatalf("handed %+v", got)
	}
	e.AssertReceipts(0, 0, 0)
}

// The effective body ceiling, the smaller of the global and the operation's,
// bounds the bytes read for a declared and for a chunked body: exactly the
// ceiling is handed on whole with its length declared, one byte more is
// refused with 413 and never handed on.
func TestEnforcementBodyCeiling(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.Policy(e.A, false)
	p.Operations = append(p.Operations,
		policy.Operation{ID: "large", API: "a", Method: "POST", Target: "/a/large", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(4096, gatewaytest.AnyObject)},
		policy.Operation{ID: "small", API: "a", Method: "POST", Target: "/a/small", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(1024, gatewaytest.AnyObject)},
		policy.Operation{ID: "equal", API: "a", Method: "POST", Target: "/a/equal", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(2048, gatewaytest.AnyObject)},
	)
	const global = 2048
	_, _, f := serveEnforcement(e, p, pipeline.Limits{MaxBodyBytes: global})
	routed := []string{"INGRESS", "CAPTURE", "CANONICAL", "ROUTE", "ACCESS"}
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
				stage, reason := gatewaytest.SizeRefusal(framing, size, global)
				want := gatewaytest.ExpectedStages(nil, "INGRESS", audit.StageReject)
				if stage == "BODY" {
					want = gatewaytest.Public(gatewaytest.ExpectedStages(routed, "BODY", audit.StageReject))
				}
				_, id := gatewaytest.RequestID(&http.Response{StatusCode: status}, reply)
				ev := eventOf(e, id, 1)
				if got, _ := ev["reason"].(string); status != http.StatusRequestEntityTooLarge || ev["stage"] != stage || got != reason ||
					ev["error"] != "payload_too_large" || !gatewaytest.SameStages(ev["stages"], want) {
					t.Errorf("%s: status %d (%s), event %v, want 413 at %s", name, status, reply, ev, stage)
				}
				if n := len(f.handed()); n != handed {
					t.Fatalf("%s: %d handed on, want %d: a refused body was forwarded", name, n, handed)
				}
			}
		}
	}
	e.AssertReceipts(0, 0, 0)
}

// Rate limits count admitted requests per verified subject; a refusal is
// answered at the RATE stage and not handed on, and a publication keeps the
// counters, so a new generation forgives nothing.
func TestEnforcementRateLimit(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.ProtectedPolicy()
	p.Operations[0].Rate = gatewaytest.Rate(2, 60)
	c, _, f := serveEnforcement(e, p, pipeline.Limits{})
	get := func(subject string) (int, string) {
		resp, body := e.Exchange(http.MethodGet, "/a/x", "", "", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, subject))
		_, id := gatewaytest.RequestID(resp, body)
		return resp.StatusCode, id
	}
	for i := range 2 {
		if code, _ := get("alice"); code != http.StatusOK {
			t.Fatalf("alice request %d: %d", i+1, code)
		}
	}
	code, id := get("alice")
	if code != http.StatusTooManyRequests {
		t.Fatalf("third alice request: %d", code)
	}
	if ev := eventOf(e, id, 1); ev["stage"] != "RATE" || ev["error"] != "rate_limited" || ev["reason"] != "quota_exceeded" {
		t.Fatalf("refusal event %v", ev)
	}
	if code, _ := get("bob"); code != http.StatusOK {
		t.Fatalf("bob has his own counter: %d", code)
	}

	next := p
	next.Roles = append(slices.Clone(p.Roles), policy.Role{ID: "OTHER"})
	if outcome, status := c.Publish(context.Background(), "test", controller.Change{ID: "rate-continuity", Expected: 1, Policy: gatewaytest.MustJSON(next)}); status != http.StatusOK {
		t.Fatalf("publication: %d %+v", status, outcome)
	}
	if code, _ := get("alice"); code != http.StatusTooManyRequests {
		t.Fatalf("alice after the publication: %d, want 429", code)
	}
	if n := len(f.handed()); n != 3 {
		t.Fatalf("%d requests handed on, want 3", n)
	}
	e.AssertReceipts(0, 0, 0)
}

// HTTP/2 reads an unparseable Content-Length as 0 and keeps the stream open
// (net/http/internal/http2 server.go, processHeaders); such a request is
// refused at ingress, as HTTP/1 refuses it, and never reaches an upstream.
func TestUnparsedContentLength(t *testing.T) {
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

// A refused HTTP/1 request with an unread body closes its connection; an
// HTTP/2 one does not, since that would end every stream on the connection.
func TestRefusalCloseOnlyHTTP1(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	_, h, _ := serveEnforcement(e, e.Policy(e.A, false), pipeline.Limits{})
	for major, want := range map[int]string{1: "close", 2: ""} {
		req := httptest.NewRequest(http.MethodGet, "/a/x", strings.NewReader("unexpected"))
		req.ProtoMajor = major
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Connection") != want {
			t.Errorf("HTTP/%d: %d, Connection %q; want 400, %q", major, rec.Code, rec.Header().Get("Connection"), want)
		}
	}
}
