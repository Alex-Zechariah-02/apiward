// Fetch JSON array bodies: only validated arrays reach the upstream.

package integration

import (
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestFetchArrayBodiesReachOnlyValidatedUpstream(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.ProtectedPolicy()
	p.Operations[1].Body = gatewaytest.JSONBody(256, `{"type":"array","minItems":1,"maxItems":2,"items":{"type":"object","additionalProperties":false,"required":["item","quantity"],"properties":{"item":{"type":"string","minLength":7,"maxLength":7},"quantity":{"type":"integer","minimum":1,"maximum":50}}}}`)
	gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	for _, tc := range []struct {
		body, contentType string
		status            int
	}{
		{`[ {"item":"ITM-001", "quantity":2} ]`, "application/json", 200},
		{`[]`, "application/json", 400},
		{`[null]`, "application/json", 400},
		{`[{"item":"ITM-001","quantity":51}]`, "application/json", 400},
		{`[{"item":"ITM-001","quantity":2,"price_sen":1}]`, "application/json", 400},
		{`[{"item":"ITM-001","quantity":2,"quantity":1}]`, "application/json", 400},
		{`[{"item":"ITM-001","quantity":1},{"item":"ITM-002","quantity":1},{"item":"ITM-003","quantity":1}]`, "application/json", 400},
		{strings.Repeat(" ", 257), "application/json", 413},
		{`[]`, "text/plain", 415},
	} {
		before := len(e.A.Receipts())
		code, body := e.Request("POST", "/a/item", tc.contentType, tc.body, gatewaytest.Bearer(t, "alice")...)
		if code != tc.status {
			t.Errorf("array %s: %d %s", tc.body, code, body)
		}
		if tc.status == 200 {
			receipts := e.A.Receipts()
			if len(receipts) != before+1 || receipts[len(receipts)-1].Body != tc.body {
				t.Errorf("validated representation changed: %+v", receipts)
			}
		} else if len(e.A.Receipts()) != before {
			t.Errorf("invalid array was forwarded: %s", tc.body)
		}
	}
	e.AssertReceipts(1, 0, 0)
}
