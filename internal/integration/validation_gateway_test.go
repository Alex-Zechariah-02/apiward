// Validation and schema keywords through the gateway.

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// Every invalid write is refused before the fixture: no receipt anywhere, no
// state change, and an event at the stage that refused it. Valid writes,
// including boundary values, reach the intended fixture with the exact bytes
// sent.
func TestValidationThroughGateway(t *testing.T) {
	e, fixtures := newFixtureEnv(t)
	orders, inventory := fixtures["orders"], fixtures["inventory"]
	customer := "Authorization: Bearer " + gatewaytest.Issuer.TokenFor(t, "cust-001") + "\r\n"
	staff := "Authorization: Bearer " + gatewaytest.Issuer.TokenFor(t, "staff-01") + "\r\n"

	request := func(method, path, credential, headers, body string) string {
		return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n%s%sContent-Length: %d\r\n\r\n%s",
			method, path, credential, headers, len(body), body)
	}
	create := func(headers, body string) string { return request("POST", "/orders", customer, headers, body) }
	adjust := func(body string) string {
		return request("PATCH", "/inventory/items/ITM-001", staff, "Content-Type: application/json\r\n", body)
	}
	jsonType := "Content-Type: application/json\r\n"
	order := func(fields string) string {
		return create(jsonType, `{"customer":"cust-001","item":"ITM-001",`+fields+`}`)
	}

	refused := []struct {
		name, request string
		halfClose     bool
		status        int
		stage, reason string
	}{
		{"malformed JSON", create(jsonType, `{"cu`), false, 400, "BODY", "malformed_json"},
		{"empty body", create(jsonType, ``), false, 400, "BODY", "malformed_json"},
		{"truncated body", strings.Replace(create(jsonType, `{"customer":"cust-001"`), "Content-Length: 22", "Content-Length: 60", 1), true, 400, "BODY", "read_failed"},
		{"second JSON value", order(`"quantity":1}{"quantity":40`), false, 400, "BODY", "trailing_data"},
		{"trailing text", create(jsonType, `{"customer":"cust-001","item":"ITM-001","quantity":1} x`), false, 400, "BODY", "trailing_data"},
		{"invalid UTF-8", create(jsonType, "{\"customer\":\"cust-001\xff\",\"item\":\"ITM-001\",\"quantity\":1}"), false, 400, "BODY", "invalid_encoding"},
		{"lone surrogate", order(`"quantity":1,"x":"\ud800"`), false, 400, "BODY", "invalid_encoding"},
		{"repeated member", order(`"quantity":1,"quantity":40`), false, 400, "BODY", "duplicate_member"},
		{"nesting above the bound", create(jsonType, strings.Repeat(`{"a":`, 17)+"1"+strings.Repeat("}", 17)), false, 400, "BODY", "limit_exceeded"},
		{"unbounded number", order(`"quantity":1e1000`), false, 400, "BODY", "limit_exceeded"},
		{"no media type", create("", `{"customer":"cust-001","item":"ITM-001","quantity":1}`), false, 415, "BODY", "media_type"},
		{"text media type", create("Content-Type: text/plain\r\n", `{}`), false, 415, "BODY", "media_type"},
		{"other charset", create("Content-Type: application/json; charset=iso-8859-1\r\n", `{}`), false, 415, "BODY", "media_type"},
		{"unknown parameter", create("Content-Type: application/json; v=2\r\n", `{}`), false, 415, "BODY", "media_type"},
		{"malformed media type", create("Content-Type: application/json;;\r\n", `{}`), false, 415, "BODY", "media_type"},
		{"two media types", create(jsonType+jsonType, `{}`), false, 415, "BODY", "media_type"},
		{"declared length above the limit", create(jsonType, strings.Repeat(" ", 1025)), false, 413, "BODY", "too_large"},
		{"chunked body above the limit", "POST /orders HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n" + customer + jsonType +
			"Transfer-Encoding: chunked\r\n\r\n401\r\n" + strings.Repeat(" ", 1025) + "\r\n0\r\n\r\n", false, 413, "BODY", "too_large"},
		{"missing field", create(jsonType, `{"customer":"cust-001","quantity":1}`), false, 400, "VALIDATION", "schema_mismatch"},
		{"extra field", order(`"quantity":1,"price":0`), false, 400, "VALIDATION", "schema_mismatch"},
		{"quantity as text", order(`"quantity":"1"`), false, 400, "VALIDATION", "schema_mismatch"},
		{"fractional quantity", order(`"quantity":1.5`), false, 400, "VALIDATION", "schema_mismatch"},
		{"null quantity", order(`"quantity":null`), false, 400, "VALIDATION", "schema_mismatch"},
		{"object as customer", create(jsonType, `{"customer":{"id":"cust-001"},"item":"ITM-001","quantity":1}`), false, 400, "VALIDATION", "schema_mismatch"},
		{"empty customer", create(jsonType, `{"customer":"","item":"ITM-001","quantity":1}`), false, 400, "VALIDATION", "schema_mismatch"},
		{"customer above the length bound", create(jsonType, `{"customer":"`+strings.Repeat("c", 65)+`","item":"ITM-001","quantity":1}`), false, 400, "VALIDATION", "schema_mismatch"},
		{"array root", create(jsonType, `[{"customer":"cust-001","item":"ITM-001","quantity":1}]`), false, 400, "VALIDATION", "schema_mismatch"},
		{"null root", create(jsonType, `null`), false, 400, "VALIDATION", "schema_mismatch"},
		{"string root", create(jsonType, `"order"`), false, 400, "VALIDATION", "schema_mismatch"},
		{"empty object", create(jsonType, `{}`), false, 400, "VALIDATION", "schema_mismatch"},
		{"delta above the range", adjust(`{"delta":101}`), false, 400, "VALIDATION", "schema_mismatch"},
		{"delta below the range", adjust(`{"delta":-101}`), false, 400, "VALIDATION", "schema_mismatch"},
		{"body on a bodyless operation", request("GET", "/orders", staff, jsonType, `{}`), false, 400, "BODY", "unexpected_body"},
	}
	states := map[string]string{"orders": orders.State().SHA256, "inventory": inventory.State().SHA256}
	for _, tc := range refused {
		status, body := e.RawExchange(tc.request, tc.halfClose)
		var reply struct {
			Error     string `json:"error"`
			RequestID string `json:"request_id"`
		}
		json.Unmarshal([]byte(body), &reply)
		if status != tc.status {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, status, tc.status, body)
			continue
		}
		events := e.RequestEvents(reply.RequestID, 1)
		if len(events) != 1 || events[0]["kind"] != "request.rejected" || events[0]["stage"] != tc.stage || events[0]["reason"] != tc.reason {
			t.Errorf("%s: events %v, want a %s rejection with reason %s", tc.name, events, tc.stage, tc.reason)
		}
		// The client sees only the code, never the input or the validator's
		// message.
		if strings.Contains(body, "cust-001") || strings.Contains(body, "quantity") || strings.Contains(body, "schema") {
			t.Errorf("%s: reply %s echoes input or validator detail", tc.name, body)
		}
	}
	for name, n := range gatewaytest.ReceiptCounts(fixtures) {
		if n != 0 {
			t.Errorf("fixture %s received %d refused requests", name, n)
		}
	}
	if orders.State().SHA256 != states["orders"] || inventory.State().SHA256 != states["inventory"] {
		t.Fatal("a refused request changed fixture state")
	}

	// Accepted requests: the fixture receives exactly the bytes sent, with a
	// matching Content-Length, and runs the operation.
	accepted := []struct {
		name, request, body, fixture, effect string
		status                               int
	}{
		{"valid order", "", `{"customer":"cust-001","item":"ITM-002","quantity":2}`, "orders", "created ORD-1004", 201},
		{"layout and charset kept", "charset", "{ \"customer\" : \"cust-001\",\n \"item\":\"ITM-003\", \"quantity\" : 1 }\n", "orders", "created ORD-1005", 201},
		// Forwarded: the fixture's own ownership rule then refuses it.
		{"customer at the length bound", "", `{"customer":"` + strings.Repeat("c", 64) + `","item":"ITM-001","quantity":1}`, "orders", "", 403},
		{"delta at the upper bound", "adjust", `{"delta":100}`, "inventory", "ITM-001 stock 40->140", 200},
		{"delta at the lower bound", "adjust", `{"delta":-100}`, "inventory", "ITM-001 stock 140->40", 200},
	}
	for _, tc := range accepted {
		var raw string
		switch tc.request {
		case "adjust":
			raw = adjust(tc.body)
		case "charset":
			raw = create("Content-Type: Application/JSON; Charset=UTF-8\r\n", tc.body)
		default:
			raw = create(jsonType, tc.body)
		}
		status, reply := e.RawExchange(raw, false)
		target := fixtures[tc.fixture]
		receipts := target.Receipts()
		if status != tc.status || len(receipts) == 0 {
			t.Fatalf("%s: status %d (%s), %d receipts", tc.name, status, reply, len(receipts))
		}
		last := receipts[len(receipts)-1]
		if last.BodySHA256 != sha256Hex(tc.body) || last.BodyBytes != len(tc.body) || last.Effect != tc.effect {
			t.Errorf("%s: fixture received %d bytes %s effect %q, want %d bytes %s effect %q",
				tc.name, last.BodyBytes, last.BodySHA256, last.Effect, len(tc.body), sha256Hex(tc.body), tc.effect)
		}
	}
	if counts := gatewaytest.ReceiptCounts(fixtures); counts["orders"] != 3 || counts["inventory"] != 2 || counts["reports"] != 0 {
		t.Fatalf("receipts %v, want orders 3, inventory 2", counts)
	}
}

// Enumerations, ranges, lengths, null unions, nested objects and declared
// headers behave as the schema states, with the valid boundary admitted; the
// decoder limits hold at their bounds.
func TestSchemaKeywordsThroughGateway(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.KeywordPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	key := "Idempotency-Key: k-123456\r\n"
	item := func(headers, body string) string {
		return fmt.Sprintf("POST /a/item HTTP/1.1\r\nHost: gw\r\nConnection: close\r\nContent-Type: application/json\r\n%sContent-Length: %d\r\n\r\n%s", headers, len(body), body)
	}
	cases := []struct {
		name, request string
		status        int
		reason        string
	}{
		{"valid", item(key, `{"kind":"alpha","count":1}`), 200, ""},
		{"all fields at their bounds", item(key+"X-Mode: fast\r\n", `{"kind":"beta","count":5,"note":"12345678","meta":{"tag":false}}`), 200, ""},
		{"null where allowed", item(key, `{"kind":"alpha","count":3,"note":null}`), 200, ""},
		{"integer written with a fraction", item(key, `{"kind":"alpha","count":2.0}`), 200, ""},
		{"header name in another case", item("idempotency-KEY: k-123456\r\n", `{"kind":"alpha","count":1}`), 200, ""},
		{"value outside the enumeration", item(key, `{"kind":"gamma","count":1}`), 400, "schema_mismatch"},
		{"enumeration in another case", item(key, `{"kind":"Alpha","count":1}`), 400, "schema_mismatch"},
		{"count below the range", item(key, `{"kind":"alpha","count":0}`), 400, "schema_mismatch"},
		{"count above the range", item(key, `{"kind":"alpha","count":6}`), 400, "schema_mismatch"},
		{"count as boolean", item(key, `{"kind":"alpha","count":true}`), 400, "schema_mismatch"},
		{"note above the length bound", item(key, `{"kind":"alpha","count":1,"note":"123456789"}`), 400, "schema_mismatch"},
		{"note as number", item(key, `{"kind":"alpha","count":1,"note":7}`), 400, "schema_mismatch"},
		{"nested unknown field", item(key, `{"kind":"alpha","count":1,"meta":{"tag":true,"x":1}}`), 400, "schema_mismatch"},
		{"nested wrong type", item(key, `{"kind":"alpha","count":1,"meta":{"tag":"yes"}}`), 400, "schema_mismatch"},
		{"missing required header", item("", `{"kind":"alpha","count":1}`), 400, "header_mismatch"},
		{"header below the length bound", item("Idempotency-Key: short\r\n", `{"kind":"alpha","count":1}`), 400, "header_mismatch"},
		{"header outside its enumeration", item(key+"X-Mode: slow\r\n", `{"kind":"alpha","count":1}`), 400, "header_mismatch"},
		{"repeated declared header", item(key+key, `{"kind":"alpha","count":1}`), 400, "repeated_header"},
		{"header-only operation without the header", "GET /a/probe HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n", 400, "header_mismatch"},
		{"header-only operation", "GET /a/probe HTTP/1.1\r\nHost: gw\r\nConnection: close\r\nX-Probe: on\r\n\r\n", 200, ""},
		{"values at the decoder bound", bulk(policy.MaxJSONValues - 1), 200, ""},
		{"values above the decoder bound", bulk(policy.MaxJSONValues), 400, "limit_exceeded"},
	}
	forwarded := 0
	for _, tc := range cases {
		started := time.Now()
		status, body := e.RawExchange(tc.request, false)
		elapsed := time.Since(started)
		if status != tc.status {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, status, tc.status, body)
			continue
		}
		if elapsed > 2*time.Second {
			t.Errorf("%s: took %v", tc.name, elapsed)
		}
		if tc.status == 200 {
			forwarded++
			continue
		}
		_, id := gatewaytest.RequestID(&http.Response{StatusCode: status}, body)
		if events := e.RequestEvents(id, 1); len(events) != 1 || events[0]["reason"] != tc.reason {
			t.Errorf("%s: events %v, want reason %s", tc.name, events, tc.reason)
		}
	}
	e.AssertReceipts(forwarded, 0, 0)
}
