// Startup resource failures and graceful stop of the gateway process.

package integration

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// A resource the gateway cannot acquire stops its startup with status 1 and a
// message naming it, and whatever it acquired is released again: no listener
// stays open and the database is free for its next owner. A database that
// another gateway holds is never shared.
func TestNativeStartupResourceFailures(t *testing.T) {
	occupy := func(t *testing.T, addr string) {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
	}
	cases := []struct {
		name    string
		prepare func(t *testing.T, e *gatewaytest.Env) []string // returns the gateway's addresses that must stay closed
		cause   string
	}{
		{"data address in use", func(t *testing.T, e *gatewaytest.Env) []string { occupy(t, e.DataAddr); return []string{e.Admin} }, "data listener"},
		{"admin address in use", func(t *testing.T, e *gatewaytest.Env) []string { occupy(t, e.Admin); return []string{e.DataAddr} }, "admin listener"},
		{"audit log cannot be opened", func(t *testing.T, e *gatewaytest.Env) []string {
			if err := os.Mkdir(e.AuditLog, 0o700); err != nil {
				t.Fatal(err)
			}
			return []string{e.DataAddr, e.Admin}
		}, "audit log"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			closed := tc.prepare(t, e)
			e.Run(gatewaytest.Binaries.Plain)
			if code := e.WaitExit(); code != gatewaytest.ExitFailed || !strings.Contains(e.Output.String(), tc.cause) {
				t.Fatalf("exit %d, want %d with %q\n%s", code, gatewaytest.ExitFailed, tc.cause, e.Output)
			}
			for _, addr := range closed {
				if gatewaytest.Dialable(addr) {
					t.Fatalf("%s is open after the failed start", addr)
				}
			}
			st, err := store.OpenStore(e.Database)
			if err != nil {
				t.Fatalf("the database is held: %v", err)
			}
			st.Close()
		})
	}

	t.Run("database held by another gateway", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		generation := e.Status().Generation

		second := gatewaytest.NewEnv(t)
		settings := second.NativeSettings()
		gatewaytest.Section(settings, "gateway")["database"] = e.Database
		second.WriteNative(settings)
		second.Run(gatewaytest.Binaries.Plain)
		if code := second.WaitExit(); code != gatewaytest.ExitFailed || !strings.Contains(second.Output.String(), "held by another gateway process") {
			t.Fatalf("second gateway beside the first: exit %d\n%s", code, second.Output)
		}
		if gatewaytest.Dialable(second.DataAddr) || gatewaytest.Dialable(second.Admin) {
			t.Fatal("the refused gateway opened a listener")
		}
		if _, err := os.Stat(second.AuditLog); !os.IsNotExist(err) {
			t.Fatalf("the refused gateway opened an audit log: %v", err)
		}
		if s := e.Status(); s.Generation != generation {
			t.Fatalf("the first gateway changed: %+v", s)
		}

		// Once the first gateway has stopped, the second owns the deployment,
		// and the first is refused in its turn.
		e.Stop()
		second.Start(gatewaytest.Binaries.Plain)
		if s := second.Status(); s.Generation != generation || s.Admission != "ready" {
			t.Fatalf("second owner %+v, want generation %s", s, generation)
		}
		e.Run(gatewaytest.Binaries.Plain)
		if code := e.WaitExit(); code != gatewaytest.ExitFailed || !strings.Contains(e.Output.String(), "held by another gateway process") {
			t.Fatalf("first gateway beside the second: exit %d\n%s", code, e.Output)
		}
		if code, body := second.Get("/a/x"); code != http.StatusOK || body != "A ok" {
			t.Fatalf("second gateway after the refused start: %d %q", code, body)
		}
	})
}

// The native process stops gracefully on Ctrl+Break (os.Interrupt): from the
// signal on no new request is admitted and the protected status says it is
// stopping, while a request admitted before finishes; the listeners close,
// the process exits with status 0 and the next start serves the same
// generation. A second signal forces the exit with status 2.
func TestNativeGracefulStop(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Interruptible = true
	holdFile, release := filepath.Join(e.Dir, "hold"), filepath.Join(e.Dir, "release")
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_HOLD_PATH=/a/held", "GATEWAY_HOLD_FILE="+holdFile, "GATEWAY_HOLD_RELEASE="+release)
	generation := e.Status().Generation

	idle, err := net.DialTimeout("tcp", e.DataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	io.WriteString(idle, "GET /a/x HTTP/1.1\r\nHost: gw\r\n\r\n")
	idleReader := bufio.NewReader(idle)
	if resp, err := http.ReadResponse(idleReader, nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("request on the kept connection: %v", err)
	} else {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	held := make(chan string, 1)
	go func() {
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Get("http://" + e.DataAddr + "/a/held")
		if err != nil {
			held <- err.Error()
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		held <- fmt.Sprintf("%d %s", resp.StatusCode, body)
	}()
	waitForFile(t, holdFile)

	gatewaytest.Interrupt(t, e.Process)
	e.WaitOutput(`"msg":"stopping","signal":"interrupt"`)
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "the data listener to close", func() bool { return !gatewaytest.Dialable(e.DataAddr) })
	if s := e.Status(); s.Admission != "stopping" || s.State != "stopping" {
		t.Fatalf("status while stopping %+v", s)
	}
	if health := e.Health(); health != "unavailable" {
		t.Fatalf("health while stopping %q", health)
	}
	idle.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := idleReader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("the idle connection was not closed: %v", err)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := <-held; got != "200 A ok" {
		t.Fatalf("request admitted before the stop: %s", got)
	}
	if code := e.WaitExit(); code != gatewaytest.ExitStopped {
		t.Fatalf("exit status %d\n%s", code, e.Output)
	}
	if !strings.Contains(e.Output.String(), `"msg":"stopped"`) || gatewaytest.Dialable(e.Admin) {
		t.Fatalf("stop not completed\n%s", e.Output)
	}
	e.AssertReceipts(2, 0, 0)

	e.Interruptible = false
	e.Start(gatewaytest.Binaries.Plain)
	if s := e.Status(); s.Generation != generation {
		t.Fatalf("generation %s after the restart, want %s", s.Generation, generation)
	}
	if gatewaytest.CountKind(e.AuditEvents(), "audit.recovered") != 0 {
		t.Fatal("the restart found an incomplete audit record")
	}

	t.Run("second signal", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.Interruptible = true
		holdFile, release := filepath.Join(e.Dir, "hold"), filepath.Join(e.Dir, "release")
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_HOLD_PATH=/a/held", "GATEWAY_HOLD_FILE="+holdFile, "GATEWAY_HOLD_RELEASE="+release)
		go (&http.Client{Timeout: 30 * time.Second}).Get("http://" + e.DataAddr + "/a/held")
		waitForFile(t, holdFile)
		gatewaytest.Interrupt(t, e.Process)
		e.WaitOutput(`"msg":"stopping"`)
		gatewaytest.Interrupt(t, e.Process)
		if code := e.WaitExit(); code != gatewaytest.ExitForced || !strings.Contains(e.Output.String(), "forced exit") {
			t.Fatalf("exit status %d after two signals\n%s", code, e.Output)
		}
		if strings.Contains(e.Output.String(), `"msg":"stopped"`) {
			t.Fatal("a forced exit was reported as a completed stop")
		}
	})
}
