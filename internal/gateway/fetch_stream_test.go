// Fetch live event stream: a stalled viewer cannot block enforcement.

package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestFetchStalledViewerCannotBlockEnforcement(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	controller, _ := serveNative(e, e.Policy(e.A, true), forwardTimeouts)
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	address, err := net.ResolveTCPAddr("tcp", e.Admin)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	// A deliberately small receive buffer makes the viewer's TCP backpressure
	// real without a large traffic fixture or any fixed-port listener.
	if err := connection.SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(connection, "GET /admin/events/stream HTTP/1.1\r\nHost: %s\r\nAccept: text/event-stream\r\nCookie: %s=%s\r\n\r\n", e.Admin, gatewaytest.AdminCookie, admin.Cookie)
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("stream: %d", response.StatusCode)
	}
	start := time.Now()
	for i := range 2000 {
		controller.Observations().Record(audit.Event{RequestID: fmt.Sprint(i), Time: time.Now().UTC(), Method: "GET", Path: "/a/" + strings.Repeat("x", 200), API: "a", Operation: "read-a", Decision: "forwarded", Stage: "FORWARD", Status: 200})
	}
	if code, body := e.Get("/a/actual-probe"); code != 200 {
		t.Fatalf("stalled viewer affected admission: %d %s", code, body)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("viewer delayed observation/admission: %v", elapsed)
	}
	e.AssertReceipts(1, 0, 0)
	if err := connection.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(response.Body)
	dropped := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "event: dropped" {
			dropped = true
			continue
		}
		if dropped && strings.HasPrefix(line, "data: ") {
			var notice struct {
				Count uint64 `json:"count"`
			}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &notice); err != nil || notice.Count == 0 {
				t.Fatalf("drop notice: %s (%v)", line, err)
			}
			return
		}
	}
	t.Fatalf("viewer loss was not disclosed: %v", scanner.Err())
}
