// Native stop drains queued audit events.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// draining returns the pending count of the gateway's drain line, or -1.
func draining(e *gatewaytest.Env) int {
	m := regexp.MustCompile(`"msg":"draining the audit log","pending":(\d+)`).FindStringSubmatch(e.Output.String())
	if m == nil {
		return -1
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// refuse sends n denied requests and returns their request identities.
func refuse(e *gatewaytest.Env, n int) []string {
	e.T.Helper()
	ids := make([]string, 0, n)
	for range n {
		resp, body := e.Exchange(http.MethodGet, "/d", "", "")
		_, id := gatewaytest.RequestID(resp, body)
		if resp.StatusCode != http.StatusForbidden || id == "" {
			e.T.Fatalf("denied request: %d %s", resp.StatusCode, body)
		}
		ids = append(ids, id)
	}
	return ids
}

// holdWriter makes the gateway's writer hold before its next write and
// returns the hold file and the identity of the refusal whose event the
// writer then holds.
func holdWriter(e *gatewaytest.Env) (string, string) {
	e.T.Helper()
	// The startup events are written first, so the held batch is the
	// refusal's.
	e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "controller.reconciled") > 0 })
	hold := filepath.Join(e.Dir, "audit-hold")
	if err := os.WriteFile(hold, nil, 0o600); err != nil {
		e.T.Fatal(err)
	}
	held := refuse(e, 1)[0]
	waitForFile(e.T, hold+".held")
	return hold, held
}

// rejectedIDs counts the request.rejected records of each request.
func rejectedIDs(events []map[string]any) map[string]int {
	ids := map[string]int{}
	for _, ev := range events {
		if ev["kind"] == "request.rejected" {
			ids[ev["request_id"].(string)]++
		}
	}
	return ids
}

func lossOf(events []map[string]any) int {
	n := 0
	for _, ev := range events {
		if ev["kind"] == "audit.loss" {
			n += int(ev["lost"].(float64))
		}
	}
	return n
}

// The native process, stopped by a real Ctrl+Break, writes every event it
// accepted before the stop, also when they wait behind a writer held until
// the drain has begun: the process exits with status 0, and the reopened audit
// file holds each of them once. Events refused because the queue was full are
// counted in the file, exactly. The next start finds a complete file.
func TestNativeStopDrainsQueuedEvents(t *testing.T) {
	for _, tc := range []struct {
		name   string
		queued int
		lost   int
	}{
		{"events behind a held writer", 300, 0},
		{"more events than the queue holds", audit.AuditQueueSize + 10, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			e.Interruptible = true
			e.Start(gatewaytest.Binaries.Fault, "GATEWAY_AUDIT_HOLD="+filepath.Join(e.Dir, "audit-hold"))
			hold, held := holdWriter(e)
			ids := append([]string{held}, refuse(e, tc.queued)...)

			gatewaytest.Interrupt(t, e.Process)
			e.WaitOutput(`"msg":"draining the audit log"`)
			// The held event and every queued one are pending when the drain
			// begins; nothing was written since the writer was held.
			if pending := draining(e); pending != len(ids)-tc.lost {
				t.Fatalf("pending %d at the drain, want %d", pending, len(ids)-tc.lost)
			}
			if err := os.Remove(hold); err != nil {
				t.Fatal(err)
			}
			if code := e.WaitExit(); code != gatewaytest.ExitStopped {
				t.Fatalf("exit status %d\n%s", code, e.Output)
			}
			if !strings.Contains(e.Output.String(), `"msg":"stopped"`) || strings.Contains(e.Output.String(), "stop incomplete") {
				t.Fatalf("stop not reported complete\n%s", e.Output)
			}

			events := e.AuditEvents()
			recorded := rejectedIDs(events)
			for i, id := range ids {
				want := 1
				if i >= len(ids)-tc.lost {
					want = 0 // refused: the queue was full
				}
				if recorded[id] != want {
					t.Fatalf("request %d (%s) recorded %d times, want %d", i, id, recorded[id], want)
				}
			}
			if loss := lossOf(events); loss != tc.lost {
				t.Fatalf("loss counted %d, want %d", loss, tc.lost)
			}

			e.Interruptible = false
			e.Start(gatewaytest.Binaries.Plain)
			if n := gatewaytest.CountKind(e.AuditEvents(), "audit.recovered"); n != 0 {
				t.Fatalf("%d incomplete records found after the graceful stop", n)
			}
		})
	}
}

// A drain that cannot finish within its bound, because the writer stays
// blocked, ends the process with status 3 and says how many accepted events
// are not confirmed written; it never reports a completed stop, and those
// events are not in the file.
func TestNativeStopReportsIncompleteDrain(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Interruptible = true
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_AUDIT_HOLD="+filepath.Join(e.Dir, "audit-hold"))
	_, held := holdWriter(e)
	ids := append([]string{held}, refuse(e, 50)...)

	gatewaytest.Interrupt(t, e.Process)
	e.WaitOutput(`"msg":"draining the audit log"`)
	started := time.Now()
	if code := e.WaitExit(); code != gatewaytest.ExitIncomplete {
		t.Fatalf("exit status %d\n%s", code, e.Output)
	}
	if elapsed := time.Since(started); elapsed < audit.AuditDrainWait-500*time.Millisecond || elapsed > audit.AuditDrainWait+5*time.Second {
		t.Fatalf("exited %s after the drain began, want about %s", elapsed, audit.AuditDrainWait)
	}
	output := e.Output.String()
	if !strings.Contains(output, `"msg":"stop incomplete"`) || !strings.Contains(output, "51 accepted events") || strings.Contains(output, `"msg":"stopped"`) {
		t.Fatalf("incomplete stop not reported\n%s", output)
	}
	recorded := rejectedIDs(e.AuditEvents())
	for _, id := range ids {
		if recorded[id] != 0 {
			t.Fatalf("request %s recorded although the writer never wrote it", id)
		}
	}
}

// A writer that fails, in its sync or in every write, leaves accepted events
// unwritten: the stop exits with status 3 and says so, and no credential
// reaches the output.
func TestNativeStopReportsAuditFailure(t *testing.T) {
	for _, fault := range []string{"audit-sync", "audit-full"} {
		t.Run(fault, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
			e.Interruptible = true
			e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT="+fault)
			gatewaytest.WaitFor(t, time.Now().Add(10*time.Second), "the audit failure", func() bool {
				return strings.Contains(e.Output.String(), "audit log failed")
			})
			token := gatewaytest.Issuer.TokenFor(t, "alice")
			if code, _ := e.Get("/a/x", "Authorization", "Bearer "+token); code != http.StatusServiceUnavailable {
				t.Fatalf("admission with the failed audit log: %d", code)
			}
			refuse(e, 3)
			e.AssertReceipts(0, 0, 0)
			gatewaytest.Interrupt(t, e.Process)
			if code := e.WaitExit(); code != gatewaytest.ExitIncomplete {
				t.Fatalf("exit status %d\n%s", code, e.Output)
			}
			output := e.Output.String()
			if !strings.Contains(output, `"msg":"stop incomplete"`) || !strings.Contains(output, "audit log incomplete") || strings.Contains(output, `"msg":"stopped"`) {
				t.Fatalf("failed audit log not reported\n%s", output)
			}
			if strings.Contains(output, token[:40]) || strings.Contains(output, "Bearer") {
				t.Fatalf("the output holds a credential\n%s", output)
			}
		})
	}
}
