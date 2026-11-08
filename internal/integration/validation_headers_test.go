// Validated headers cannot be removed by the connection.

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// bulk is a request for /a/bulk whose body holds values JSON values: an
// object with one array member.
func bulk(values int) string {
	body := `{"v":[` + strings.TrimSuffix(strings.Repeat("1,", values-1), ",") + `]}`
	return fmt.Sprintf("POST /a/bulk HTTP/1.1\r\nHost: gw\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

// The proxy removes every field the client names in Connection, as an HTTP
// intermediary must, so a request naming a header the operation validates,
// or Content-Type when it validates a body, is refused before it is
// forwarded: the upstream would not receive what was checked. The same
// request without the nomination is forwarded with the header.
func TestConnectionCannotRemoveValidatedHeaders(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.KeywordPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	probe := func(connection string) string {
		return "GET /a/probe HTTP/1.1\r\nHost: gw\r\n" + connection + "X-Probe: on\r\n\r\n"
	}
	item := func(connection string) string {
		body := `{"kind":"alpha","count":1}`
		return fmt.Sprintf("POST /a/item HTTP/1.1\r\nHost: gw\r\nConnection: %s\r\nContent-Type: application/json\r\nIdempotency-Key: k-123456\r\nContent-Length: %d\r\n\r\n%s",
			connection, len(body), body)
	}
	if status, body := e.RawExchange(probe("Connection: close\r\n"), false); status != http.StatusOK || e.A.Count() != 1 || e.A.Receipts()[0].Headers.Get("X-Probe") != "on" {
		t.Fatalf("validated header not named: status %d (%s), receipts %+v", status, body, e.A.Receipts())
	}
	cases := []struct {
		name, request string
	}{
		{"validated header named", probe("Connection: close, X-Probe\r\n")},
		{"named in a second field and another case", probe("Connection: close\r\nConnection: x-probe\r\n")},
		{"required header named", item("close, Idempotency-Key")},
		{"media type named", item("close, Content-Type")},
	}
	for _, tc := range cases {
		status, body := e.RawExchange(tc.request, false)
		_, id := gatewaytest.RequestID(&http.Response{StatusCode: status}, body)
		events := e.RequestEvents(id, 1)
		if status != http.StatusBadRequest || len(events) != 1 || events[0]["stage"] != "VALIDATION" || events[0]["reason"] != "connection_nominated" {
			t.Errorf("%s: status %d (%s), events %v", tc.name, status, body, events)
		}
	}
	e.AssertReceipts(1, 0, 0)
}
