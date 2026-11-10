// Forwarding under concurrency, routing table and refusals.

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// Concurrent allowed and denied requests while publications move API a
// between A and B: every admitted request reaches the upstream of the
// generation it captured, its outcome event names that generation, and no
// denied request reaches any upstream.
func TestNativeForwardingUnderConcurrency(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	toA, toB := e.Policy(e.A, false), e.Policy(e.B, false)
	c, _ := serveNative(e, toA, forwardTimeouts)
	receiverOf := map[string]string{c.Current().ID: "A"}
	var mu sync.Mutex

	done := make(chan struct{})
	var publisher sync.WaitGroup
	publisher.Go(func() {
		expected := int64(1)
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			policy, name := toB, "B"
			if i%2 == 1 {
				policy, name = toA, "A"
			}
			outcome, status := c.Publish(context.Background(), "test", controller.Change{ID: fmt.Sprintf("concurrent-%d", i), Expected: expected, Policy: gatewaytest.MustJSON(policy)})
			if status != http.StatusOK {
				t.Errorf("publication %d: %d %+v", i, status, outcome)
				return
			}
			mu.Lock()
			receiverOf[outcome.Generation] = name
			mu.Unlock()
			expected = outcome.Revision
		}
	})
	var clients sync.WaitGroup
	for range 8 {
		clients.Go(func() {
			for range 25 {
				if code, body, err := fetch(e.DataAddr, "/a/x"); err != nil || code != http.StatusOK || (body != "A ok" && body != "B ok") {
					t.Errorf("allowed request: %d %q %v", code, body, err)
				}
			}
		})
	}
	for range 4 {
		clients.Go(func() {
			for range 10 {
				if code, _, err := fetch(e.DataAddr, "/d"); err != nil || code != http.StatusForbidden {
					t.Errorf("denied request: %d %v", code, err)
				}
			}
		})
	}
	clients.Wait()
	close(done)
	publisher.Wait()

	receipts := map[string][]gatewaytest.Receipt{"A": e.A.Receipts(), "B": e.B.Receipts()}
	if total := len(receipts["A"]) + len(receipts["B"]); total != 200 || e.C.Count() != 0 {
		t.Fatalf("receipts A=%d B=%d C=%d, want 200 in all at A and B", len(receipts["A"]), len(receipts["B"]), e.C.Count())
	}
	outcomes := map[string]string{}
	for _, ev := range e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "request.forwarded") == 200 }) {
		if ev["kind"] == "request.forwarded" {
			outcomes[ev["request_id"].(string)], _ = ev["generation"].(string)
		}
	}
	for name, got := range receipts {
		for _, r := range got {
			if receiverOf[r.Generation] != name || outcomes[r.RequestID] != r.Generation || r.Path != "/a/x" {
				t.Fatalf("%s received a request under %s (whose upstream is %q), outcome under %s", name, r.Generation, receiverOf[r.Generation], outcomes[r.RequestID])
			}
		}
	}
	t.Logf("%d generations, receipts A=%d B=%d", len(receiverOf), len(receipts["A"]), len(receipts["B"]))
}

// The forwarded target is the admitted one: canonical path matching decides
// the operation and the upstream receives the client's path in its received
// encoding and its query byte for byte. Targets the gateway refuses, and
// tunnels and protocol switches, reach no upstream.
func TestNativeForwardingRoutingTable(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	policy := policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "A", Dial: e.A.Addr}, {ID: "B", Dial: e.B.Addr}},
		APIs:          []policy.API{{ID: "orders", Upstream: "A"}, {ID: "reports", Upstream: "B"}},
		Operations: []policy.Operation{
			{ID: "reports", API: "reports", Method: "GET", Target: "/reports", Access: "allow", Auth: "none"},
			{ID: "order", API: "orders", Method: "GET", Target: "/orders/*", Access: "allow", Auth: "none"},
			{ID: "create", API: "orders", Method: "POST", Target: "/orders", Access: "allow", Auth: "none", Body: gatewaytest.JSONBody(1024, gatewaytest.AnyObject)},
			{ID: "archive", API: "orders", Method: "DELETE", Target: "/orders/archive", Access: "deny", Auth: "none"},
		},
	}
	c, _ := serveNative(e, policy, forwardTimeouts)

	rows := []struct {
		request string
		status  int
		to      *gatewaytest.Receiver
		target  string // raw target at the receiver
		path    string // decoded path at the receiver
	}{
		{"GET /orders/42 HTTP/1.1", 200, e.A, "/orders/42", "/orders/42"},
		{"GET /orders/42/items HTTP/1.1", 200, e.A, "/orders/42/items", "/orders/42/items"},
		{"GET /orders/42?x=1&y=2 HTTP/1.1", 200, e.A, "/orders/42?x=1&y=2", "/orders/42"},
		{"GET /orders/42?b=1;c=2&d=%zz&e=%20f HTTP/1.1", 200, e.A, "/orders/42?b=1;c=2&d=%zz&e=%20f", "/orders/42"},
		{"GET /orders/42? HTTP/1.1", 200, e.A, "/orders/42?", "/orders/42"},
		{"GET /orders/%41 HTTP/1.1", 200, e.A, "/orders/%41", "/orders/A"},
		{"GET /orders/a;b=c HTTP/1.1", 200, e.A, "/orders/a;b=c", "/orders/a;b=c"},
		{"GET /orders/%3Bx HTTP/1.1", 200, e.A, "/orders/%3Bx", "/orders/;x"},
		{"GET /reports HTTP/1.1", 200, e.B, "/reports", "/reports"},
		{"GET /reports HTTP/1.0", 200, e.B, "/reports", "/reports"},
		{"GET /orders HTTP/1.1", 405, nil, "", ""},
		{"GET /orders/ HTTP/1.1", 404, nil, "", ""},
		{"GET /Orders/42 HTTP/1.1", 404, nil, "", ""},
		{"GET /ordersX HTTP/1.1", 404, nil, "", ""},
		{"GET /orders/%2F42 HTTP/1.1", 400, nil, "", ""},
		{"GET /orders/../reports HTTP/1.1", 400, nil, "", ""},
		{"GET /orders/%2e%2e/reports HTTP/1.1", 400, nil, "", ""},
		{"GET /orders//42 HTTP/1.1", 400, nil, "", ""},
		{"GET /orders/%252F HTTP/1.1", 400, nil, "", ""},
		{"GET /orders/a%5Cb HTTP/1.1", 400, nil, "", ""},
		{"get /orders/42 HTTP/1.1", 405, nil, "", ""},
		{"HEAD /orders/42 HTTP/1.1", 405, nil, "", ""},
		{"DELETE /orders/archive HTTP/1.1", 403, nil, "", ""},
		{"GET http://" + e.B.Addr + "/reports HTTP/1.1", 400, nil, "", ""},
		{"CONNECT " + e.B.Addr + " HTTP/1.1", 400, nil, "", ""},
		{"OPTIONS * HTTP/1.1", 400, nil, "", ""},
	}
	for _, r := range rows {
		e.ResetReceivers()
		code, _ := e.Raw(r.request + "\r\nHost: gw\r\nConnection: close\r\n\r\n")
		if code != r.status {
			t.Errorf("%s: status %d, want %d", r.request, code, r.status)
			continue
		}
		total := e.A.Count() + e.B.Count() + e.C.Count()
		if r.to == nil {
			if total != 0 {
				t.Errorf("%s: a refused request reached an upstream", r.request)
			}
			continue
		}
		got := r.to.Receipts()
		if total != 1 || len(got) != 1 || got[0].Target != r.target || got[0].Path != r.path || got[0].Method != "GET" {
			t.Errorf("%s: receipts %+v (total %d), want one at %s with target %q path %q", r.request, got, total, r.to.Name, r.target, r.path)
		}
	}

	// Protocol switches and tunnels are refused at ingress and counted in
	// the ingress summary, with the absolute-form and asterisk targets and
	// the tunnel above.
	switches := []string{
		"GET /orders/42 HTTP/1.1\r\nHost: gw\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		"GET /orders/42 HTTP/1.1\r\nHost: gw\r\nUpgrade: websocket\r\n\r\n",
		"GET /orders/42 HTTP/1.1\r\nHost: gw\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
	}
	e.ResetReceivers()
	var ids []string
	for _, request := range switches {
		resp, body := e.RawResponse(request)
		_, id := gatewaytest.RequestID(resp, body)
		ids = append(ids, id)
		if resp.StatusCode != http.StatusBadRequest || id == "" {
			t.Errorf("%q: %d %s", request, resp.StatusCode, body)
		}
	}
	e.AssertReceipts(0, 0, 0)
	checkIngressSummary(t, e, c, map[string]int{"upgrade": 3, "target": 2, "connect": 1}, ids)
}

// Every refusal by the five controls or the audit gate happens before the
// native proxy runs: no upstream receives the request, and the admitted
// requests that follow do reach it.
func TestNativeForwardingRefusalsReachNoUpstream(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.ProtectedPolicy()
	p.Operations = append(p.Operations,
		policy.Operation{ID: "strict", API: "a", Method: "POST", Target: "/a/strict", Access: "allow", Auth: "required",
			Body: gatewaytest.JSONBody(1024, `{"type":"object","additionalProperties":true,"required":["n"],"properties":{"n":{"type":"integer"}}}`)},
		policy.Operation{ID: "limited", API: "a", Method: "GET", Target: "/a/limited", Access: "allow", Auth: "required", Rate: gatewaytest.Rate(3, 60)},
		policy.Operation{ID: "probe", API: "b", Method: "GET", Target: "/b/probe", Access: "allow", Auth: "none",
			Headers: json.RawMessage(`{"type":"object","additionalProperties":true,"required":["X-Probe"],"properties":{"X-Probe":{"type":"string","enum":["on"]}}}`)},
	)
	p.Permits = append(p.Permits, policy.Permit{Role: "WRITER", Operation: "strict"}, policy.Permit{Role: "WRITER", Operation: "limited"})
	c, logs := serveNative(e, p, forwardTimeouts)
	token := gatewaytest.Issuer.TokenFor(t, "alice")
	segments := strings.Split(token, ".")
	refusals := []struct {
		name   string
		method string
		path   string
		ctype  string
		body   string
		header []string
		status int
		stage  string
	}{
		{"no token", "GET", "/a/x", "", "", nil, 401, "JWT"},
		{"altered signature", "GET", "/a/x", "", "", []string{"Authorization", "Bearer " + segments[0] + "." + segments[1] + ".AAAA" + segments[2][4:]}, 401, "JWT"},
		{"subject without a permit", "POST", "/a/item", "application/json", `{"n":1}`, gatewaytest.Bearer(t, "bob"), 403, "RBAC"},
		{"unknown role claimed in the verified token", "POST", "/a/item", "application/json", `{"n":1}`,
			[]string{"Authorization", "Bearer " + gatewaytest.Issuer.Token(t, issuertest.Changed(issuertest.ValidClaims("bob"), map[string]any{"roles": []string{"ADMIN"}}))}, 403, "RBAC"},
		{"media type", "POST", "/a/strict", "text/plain", `{"n":1}`, []string{"Authorization", "Bearer " + token}, 415, "BODY"},
		{"malformed JSON", "POST", "/a/strict", "application/json", `{"n":`, []string{"Authorization", "Bearer " + token}, 400, "BODY"},
		{"body schema", "POST", "/a/strict", "application/json", `{"n":"one"}`, []string{"Authorization", "Bearer " + token}, 400, "VALIDATION"},
		{"header schema", "GET", "/b/probe", "", "", []string{"X-Probe", "off"}, 400, "VALIDATION"},
		{"Connection naming a gateway header", "GET", "/a/x", "", "", []string{"Authorization", "Bearer " + token, "Connection", "X-Gateway-Subject"}, 400, "INGRESS"},
	}
	var ingressIDs []string
	for _, tc := range refusals {
		resp, body := e.Exchange(tc.method, tc.path, tc.ctype, tc.body, tc.header...)
		_, id := gatewaytest.RequestID(resp, body)
		if tc.stage == "INGRESS" {
			ingressIDs = append(ingressIDs, id)
			if resp.StatusCode != tc.status {
				t.Errorf("%s: %d %s, want %d", tc.name, resp.StatusCode, body, tc.status)
			}
		} else if ev := eventOf(e, id, 1); resp.StatusCode != tc.status || ev["stage"] != tc.stage {
			t.Errorf("%s: %d %s, event %v, want %d at %s", tc.name, resp.StatusCode, body, ev, tc.status, tc.stage)
		}
		e.AssertReceipts(0, 0, 0)
	}

	// The rate rule admits three requests in its window.
	for i := range 4 {
		code, _ := e.Get("/a/limited", "Authorization", "Bearer "+token)
		if want := map[bool]int{true: http.StatusOK, false: http.StatusTooManyRequests}[i < 3]; code != want {
			t.Fatalf("rated request %d: %d, want %d", i+1, code, want)
		}
	}
	e.AssertReceipts(3, 0, 0)

	// An audit log that cannot record the admission admits nothing.
	c.Audit().Fail(errors.New("injected write failure"))
	if code, body := e.Get("/a/x", "Authorization", "Bearer "+token); code != http.StatusServiceUnavailable || !strings.Contains(body, "gateway_unavailable") {
		t.Fatalf("with a failed audit log: %d %s", code, body)
	}
	e.AssertReceipts(3, 0, 0)
	for name, text := range map[string]string{"audit log": fmt.Sprint(e.AuditEvents()), "proxy log": logs.String()} {
		if strings.Contains(text, token) || strings.Contains(text, segments[2]) {
			t.Errorf("the %s holds the token", name)
		}
	}
	for _, r := range e.A.Receipts() {
		if r.Authorization {
			t.Error("the credential reached the upstream")
		}
	}
	// Written before the admissions above, which waited for their records.
	if ev := gatewaytest.RecordOf(e.AuditEvents(), ingressIDs); ev != nil {
		t.Errorf("ingress refusal recorded on its own: %v", ev)
	}
}
