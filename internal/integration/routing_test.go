// Bound upstreams, publication and captured destinations.

package integration

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestAdmittedRequestReachesOnlyBoundUpstream(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	g := e.Status()

	if code, body := e.Get("/a/x"); code != http.StatusOK || body != "A ok" {
		t.Fatalf("admitted request: %d %q", code, body)
	}
	e.AssertReceipts(1, 0, 0)
	if got := e.A.Receipts()[0]; got.Generation != g.Generation || got.Target != "/a/x" {
		t.Fatalf("receipt %+v, want generation %s", got, g.Generation)
	}

	if code, _ := e.Get("/d"); code != http.StatusForbidden {
		t.Fatalf("denied operation: %d", code)
	}
	if code, _ := e.Get("/zzz"); code != http.StatusNotFound {
		t.Fatalf("unknown operation: %d", code)
	}
	e.AssertReceipts(1, 0, 0)

	events := e.EventsWhen(func(events []map[string]any) bool {
		return gatewaytest.CountKind(events, "request.rejected") >= 2 && gatewaytest.CountKind(events, "request.admitted") >= 1
	})
	admitted, rejected := gatewaytest.CountKind(events, "request.admitted"), gatewaytest.CountKind(events, "request.rejected")
	if admitted != 1 || rejected != 2 {
		t.Fatalf("audit admitted=%d rejected=%d, want 1 and 2", admitted, rejected)
	}
}

func TestPublicationAddsOperationWithoutReload(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	configHash := gatewaytest.FileSHA256(t, e.Config)
	e.Start(gatewaytest.Binaries.Fault)
	pid := e.Process.Process.Pid

	if code, _ := e.Get("/b/x"); code != http.StatusNotFound {
		t.Fatalf("before publication: %d", code)
	}
	outcome, code := e.Publish(controller.Change{ID: "add-b", Expected: 1, Policy: gatewaytest.MustJSON(e.Policy(e.A, true))})
	if code != http.StatusOK || outcome.Revision != 2 {
		t.Fatalf("publish: %d %+v", code, outcome)
	}
	if code, body := e.Get("/b/x"); code != http.StatusOK || body != "B ok" {
		t.Fatalf("new operation: %d %q", code, body)
	}
	if code, body := e.Get("/a/x"); code != http.StatusOK || body != "A ok" {
		t.Fatalf("existing operation: %d %q", code, body)
	}
	e.AssertReceipts(1, 1, 0)
	for _, r := range append(e.A.Receipts(), e.B.Receipts()...) {
		if r.Generation != outcome.Generation {
			t.Fatalf("receipt generation %s, want %s", r.Generation, outcome.Generation)
		}
	}
	if e.Process.Process.Pid != pid || gatewaytest.FileSHA256(t, e.Config) != configHash {
		t.Fatal("gateway process or configuration changed")
	}
}

// holdRequest sends POST /a/item with its whole body, then waits until the
// gateway signals that the request captured its generation; the gateway's
// GATEWAY_HOLD_RELEASE file keeps it there until the test releases it. A
// non-empty token is sent as the bearer credential.
func holdRequest(t *testing.T, e *gatewaytest.Env, holdFile, token string) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("tcp", e.DataAddr)
	if err != nil {
		t.Fatal(err)
	}
	credential := ""
	if token != "" {
		credential = "Authorization: Bearer " + token + "\r\n"
	}
	fmt.Fprintf(conn, "POST /a/item HTTP/1.1\r\nHost: gw\r\n%sContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"held\":true}", credential)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(holdFile); err == nil && len(data) > 0 {
			return conn, strings.TrimSpace(string(data))
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("request never captured a generation")
	return nil, ""
}

func TestInFlightRequestKeepsCapturedGeneration(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	holdFile, release := filepath.Join(e.Dir, "hold"), filepath.Join(e.Dir, "release")
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_HOLD_PATH=/a/item", "GATEWAY_HOLD_FILE="+holdFile, "GATEWAY_HOLD_RELEASE="+release)
	first := e.Status().Generation

	conn, captured := holdRequest(t, e, holdFile, "")
	defer conn.Close()
	if captured != first {
		t.Fatalf("captured %s, want %s", captured, first)
	}
	outcome, code := e.Publish(controller.Change{ID: "move-a", Expected: 1, Policy: gatewaytest.MustJSON(e.Policy(e.B, false))})
	if code != http.StatusOK {
		t.Fatalf("publish: %d %+v", code, outcome)
	}

	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("in-flight request: %v %v", resp, err)
	}
	e.AssertReceipts(1, 0, 0)
	if got := e.A.Receipts()[0].Generation; got != first {
		t.Fatalf("in-flight request reached A under %s, want %s", got, first)
	}

	if code, body := e.Request(http.MethodPost, "/a/item", "application/json", `{"n":1}`); code != http.StatusOK || body != "B ok" {
		t.Fatalf("new request: %d %q", code, body)
	}
	e.AssertReceipts(1, 1, 0)
	if got := e.B.Receipts()[0].Generation; got != outcome.Generation {
		t.Fatalf("new request reached B under %s, want %s", got, outcome.Generation)
	}

	// The events agree with the receipts: each request was matched, bound
	// and recorded under the generation it captured.
	held, later := e.A.Receipts()[0].RequestID, e.B.Receipts()[0].RequestID
	events := e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "request.forwarded") == 2 })
	for _, want := range []struct{ id, generation, upstream string }{{held, first, "A"}, {later, outcome.Generation, "B"}} {
		ev := gatewaytest.FindEvent(events, "request.forwarded", want.id)
		if ev == nil || ev["generation"] != want.generation || ev["upstream"] != want.upstream || ev["operation"] != "write-a" {
			t.Fatalf("event %v, want generation %s upstream %s", ev, want.generation, want.upstream)
		}
	}
}

// A request whose exchange fails while a publication moves its operation to
// another upstream is answered 502 and was sent once, to the destination of
// the generation it captured; it is never sent again, there or elsewhere.
func TestFailedAttemptStaysOnCapturedDestination(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault)
	captured := e.Status().Generation

	published := make(chan struct{})
	var once sync.Once
	e.A.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		once.Do(func() {
			outcome, code := e.Publish(controller.Change{ID: "move-a", Expected: 1, Policy: gatewaytest.MustJSON(e.Policy(e.B, false))})
			if code != http.StatusOK {
				t.Errorf("publish during attempt: %d %+v", code, outcome)
			}
			close(published)
		})
		// Drop the connection without a response: a transport error after
		// the request was sent.
		conn, _, _ := http.NewResponseController(w).Hijack()
		conn.Close()
		return true
	}
	code, _ := e.Get("/a/x")
	<-published
	if code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", code)
	}
	e.AssertReceipts(1, 0, 0)
	if g := e.A.Receipts()[0].Generation; g != captured {
		t.Fatalf("attempt under generation %s, want %s", g, captured)
	}
}
