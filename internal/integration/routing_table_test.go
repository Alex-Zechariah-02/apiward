// Canonical routing table and malformed input.

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func TestCanonicalRoutingTable(t *testing.T) {
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
	gatewaytest.Seed(t, e.Database, policy, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	type row struct {
		request string
		status  int
		to      *gatewaytest.Receiver
		target  string // expected raw target at the receiver
		path    string // expected decoded path at the receiver
	}
	rows := []row{
		{"GET /orders/42", 200, e.A, "/orders/42", "/orders/42"},
		{"GET /orders", 405, nil, "", ""},
		{"GET /orders/", 404, nil, "", ""},
		{"GET /Orders/42", 404, nil, "", ""},
		{"GET /orders/42/items", 200, e.A, "/orders/42/items", "/orders/42/items"},
		{"GET /ordersX", 404, nil, "", ""},
		{"GET /orders/%2F42", 400, nil, "", ""},
		{"GET /orders/../reports", 400, nil, "", ""},
		{"GET /orders/%2e%2e/reports", 400, nil, "", ""},
		{"GET /orders//42", 400, nil, "", ""},
		{"GET /orders/42?x=1&y=2", 200, e.A, "/orders/42?x=1&y=2", "/orders/42"},
		{"get /orders/42", 405, nil, "", ""},
		{"HEAD /orders/42", 405, nil, "", ""},
		{"OPTIONS /orders/42", 405, nil, "", ""},
		// Refused at ingress, like every target that is not in origin form.
		{"OPTIONS *", 400, nil, "", ""},
		{"GET /orders/%41", 200, e.A, "/orders/%41", "/orders/A"},
		{"GET /orders/%252F", 400, nil, "", ""},
		{"GET /reports/", 404, nil, "", ""},
		{"DELETE /orders/archive", 403, nil, "", ""},
		{"GET /orders/archive", 405, nil, "", ""},
		{"GET /orders/a%5Cb", 400, nil, "", ""},
		{"GET http://x/orders/42", 400, nil, "", ""},
		{"PATCH /unknown", 404, nil, "", ""},
		{"GET /reports", 200, e.B, "/reports", "/reports"},
	}
	for _, r := range rows {
		e.ResetReceivers()
		code, _ := e.Raw(r.request + " HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n")
		if code != r.status {
			t.Errorf("%s: status %d, want %d", r.request, code, r.status)
			continue
		}
		total := e.A.Count() + e.B.Count() + e.C.Count()
		if r.to == nil {
			if total != 0 {
				t.Errorf("%s: rejected request reached an upstream", r.request)
			}
			continue
		}
		got := r.to.Receipts()
		if total != 1 || len(got) != 1 || got[0].Target != r.target || got[0].Path != r.path {
			t.Errorf("%s: receipts %+v (total %d), want one at %s target %q path %q", r.request, got, total, r.to.Name, r.target, r.path)
		}
	}

	bodies := []struct {
		name        string
		contentType string
		body        string
		status      int
	}{
		{"valid JSON", "application/json", `{"item":1}`, 200},
		{"oversize", "application/json", `{"x":"` + strings.Repeat("a", 2000) + `"}`, 413},
		{"wrong media type", "text/plain", `{"item":1}`, 415},
		{"malformed JSON", "application/json", `{"item":`, 400},
	}
	for _, b := range bodies {
		e.ResetReceivers()
		code, _ := e.Request(http.MethodPost, "/orders", b.contentType, b.body)
		want := 0
		if b.status == 200 {
			want = 1
		}
		if code != b.status || e.A.Count() != want || e.B.Count()+e.C.Count() != 0 {
			t.Errorf("POST /orders %s: status %d receipts A=%d, want %d and %d", b.name, code, e.A.Count(), b.status, want)
		}
	}
	e.ResetReceivers()
	if code, _ := e.Request(http.MethodGet, "/orders/42", "", "hello"); code != http.StatusBadRequest || e.A.Count() != 0 {
		t.Errorf("body on bodyless operation: %d, receipts %d", code, e.A.Count())
	}
	if t.Failed() {
		t.Logf("gateway output:\n%s", e.Output)
	}
}

func TestForgedHeadersAndMalformedInput(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	g := e.Status().Generation

	code, _ := e.Raw("GET /a/x HTTP/1.1\r\nHost: gw\r\n" +
		"X-Gateway-Generation: forged\r\nX-Gateway-Subject: admin\r\nX-Request-Id: forged\r\n" +
		"X-Forwarded-For: 203.0.113.9\r\nX-Forwarded-Host: evil\r\nAuthorization: Bearer secret-token\r\n" +
		"X_Gateway_Generation: forged\r\nX.Gateway.Subject: admin\r\nConnection: close\r\n\r\n")
	if code != http.StatusOK {
		t.Fatalf("forged-header request: %d", code)
	}
	got := e.A.Receipts()[0]
	h := got.Headers
	switch {
	case got.Generation != g:
		t.Errorf("generation header %q, want %q", got.Generation, g)
	case h.Get("X-Gateway-Subject") != "":
		t.Error("forged subject header reached the upstream")
	case got.RequestID == "forged" || got.RequestID == "":
		t.Errorf("request id %q not replaced", got.RequestID)
	case h.Get("X-Forwarded-For") != "127.0.0.1":
		t.Errorf("X-Forwarded-For %q, want peer address only", h.Get("X-Forwarded-For"))
	case h.Get("X-Forwarded-Host") == "evil":
		t.Error("forged X-Forwarded-Host reached the upstream")
	case got.Authorization:
		t.Error("client credential reached the upstream")
	}
	// A name with '_' or '.' would read as a gateway header to an upstream
	// that maps header names to CGI-style variables.
	for _, name := range []string{"X_Gateway_Generation", "X.Gateway.Subject"} {
		if h.Get(name) != "" {
			t.Errorf("header %s reached the upstream", name)
		}
	}

	e.ResetReceivers()
	requests := []struct {
		name    string
		request string
		status  int
	}{
		{"overlong method", strings.Repeat("G", 33) + " /a/x HTTP/1.1\r\nHost: gw\r\n\r\n", 405},
		{"missing Host", "GET /a/x HTTP/1.1\r\n\r\n", 400},
		{"malformed request line", "GET\r\n\r\n", 400},
		{"declared oversize body", "POST /a/item HTTP/1.1\r\nHost: gw\r\nContent-Type: application/json\r\nContent-Length: 20000\r\n\r\n", 413},
		{"chunked body over limit", "POST /a/item HTTP/1.1\r\nHost: gw\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" +
			fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", 1100, strings.Repeat("a", 1100)), 413},
		{"chunked body on bodyless operation", "GET /a/x HTTP/1.1\r\nHost: gw\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", 400},
		{"protocol upgrade", "GET /a/x HTTP/1.1\r\nHost: gw\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", 400},
		{"gateway header named in Connection", "GET /a/x HTTP/1.1\r\nHost: gw\r\nConnection: x-gateway-generation\r\n\r\n", 400},
	}
	for _, r := range requests {
		started := time.Now()
		code, _ := e.Raw(r.request)
		t.Logf("%s: status %d after %v", r.name, code, time.Since(started).Round(time.Millisecond))
		if code != r.status {
			t.Errorf("%s: status %d, want %d", r.name, code, r.status)
		}
	}
	e.AssertReceipts(0, 0, 0)
}
