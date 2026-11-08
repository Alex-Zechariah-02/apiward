// Native stop under load, restart and kill.

package integration

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// A stop during traffic on kept connections, with administrative changes in
// flight and controller timers armed, still records every request it took:
// each upstream receipt has its admission and outcome records, each refusal a
// client received has its record, and nothing is recorded twice. The process
// exits with status 0.
func TestNativeStopUnderLoad(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	provisional := e.ProtectedPolicy()
	provisional.Roles = append(provisional.Roles, policy.Role{ID: "TRIAL"})
	provisional.Permits = append(provisional.Permits, policy.Permit{Role: "TRIAL", Operation: "read-a"})
	base := e.ProtectedPolicy()
	gatewaytest.Seed(t, e.Database, base, gatewaytest.SeedOptions{Provisional: &provisional, Deadline: time.Now().Add(time.Hour)})
	e.Interruptible = true
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	var mu sync.Mutex
	var refusals []string
	stopped := make(chan struct{})
	var wg sync.WaitGroup
	for c := range 8 {
		wg.Go(func() {
			client := &http.Client{Timeout: 10 * time.Second}
			token := gatewaytest.Issuer.TokenFor(t, "alice")
			for i := 0; ; i++ {
				select {
				case <-stopped:
					return
				default:
				}
				path := "/a/x"
				if (c+i)%3 == 0 {
					path = "/d"
				}
				req, _ := http.NewRequest(http.MethodGet, "http://"+e.DataAddr+path, http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := client.Do(req)
				if err != nil {
					time.Sleep(time.Millisecond)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if _, id := gatewaytest.RequestID(resp, string(body)); id != "" {
					mu.Lock()
					refusals = append(refusals, id)
					mu.Unlock()
				}
			}
		})
	}
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stopped:
				return
			default:
			}
			if code, _, _ := e.AdminSend(http.MethodGet, "/admin/status", "", harness.Headers(e)...); code == 0 {
				time.Sleep(time.Millisecond)
				continue
			}
			// A mutation that is refused: the request names another
			// provisional revision.
			e.AdminSend(http.MethodPost, "/admin/provisional/rollback", `{"revision":3}`, append(harness.Headers(e),
				"If-Match", `"r1"`, "Idempotency-Key", fmt.Sprintf("load-mismatch-%08d", i))...)
		}
	})
	gatewaytest.WaitFor(t, time.Now().Add(20*time.Second), "traffic", func() bool { return e.A.Count() >= 200 })
	gatewaytest.Interrupt(t, e.Process)
	code := e.WaitExit()
	close(stopped)
	wg.Wait()
	if code != gatewaytest.ExitStopped {
		t.Fatalf("exit status %d\n%s", code, e.Output)
	}

	events := e.AuditEvents()
	admitted, forwarded := map[string]int{}, map[string]int{}
	for _, ev := range events {
		id, _ := ev["request_id"].(string)
		switch ev["kind"] {
		case "request.admitted":
			admitted[id]++
		case "request.forwarded":
			forwarded[id]++
		}
	}
	for _, r := range e.A.Receipts() {
		if admitted[r.RequestID] != 1 || forwarded[r.RequestID] != 1 {
			t.Fatalf("receipt %s: %d admission and %d outcome records", r.RequestID, admitted[r.RequestID], forwarded[r.RequestID])
		}
	}
	recorded := rejectedIDs(events)
	for _, id := range refusals {
		if recorded[id] != 1 {
			t.Fatalf("refusal %s recorded %d times", id, recorded[id])
		}
	}
	if lossOf(events) != 0 {
		t.Fatalf("loss counted %d", lossOf(events))
	}
	t.Logf("%d forwarded, %d refusals received, %d records; exit %d", e.A.Count(), len(refusals), len(events), code)
}

// A graceful stop leaves the authority coherent for the next start: a
// provisional base and an override whose times pass while the gateway is
// stopped end exactly once at the restart, and are never served again; every
// committed transition is audited; the audit files, rotated many times,
// hold complete records only.
func TestNativeRestartAfterGracefulStop(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	settings := e.NativeSettings()
	gatewaytest.Section(settings, "gateway")["audit_max_bytes"] = controller.MinAuditBytes
	gatewaytest.Section(settings, "gateway")["audit_max_files"] = controller.MaxAuditFiles
	e.WriteNative(settings)
	e.Interruptible = true
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	override := e.MustOverride(harness, gatewaytest.OperationContainment("read-b", 3), `"r1"`, "restart-override-create")
	candidate := e.ProtectedPolicy()
	candidate.Roles = append(candidate.Roles, policy.Role{ID: "TRIAL"})
	candidate.Permits = append(candidate.Permits, policy.Permit{Role: "TRIAL", Operation: "read-a"})
	_, activated := e.ProvisionalFrom(harness, candidate, 1, 3, "restart-cpa")
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "carol")...); code != http.StatusOK {
		t.Fatalf("carol under the provisional base: %d", code)
	}
	refuse(e, 20)

	gatewaytest.Interrupt(t, e.Process)
	if code := e.WaitExit(); code != gatewaytest.ExitStopped {
		t.Fatalf("exit status %d\n%s", code, e.Output)
	}
	time.Sleep(time.Until(activated.Deadline.Add(500 * time.Millisecond)))
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT count(*) FROM transition WHERE id LIKE 'auto-%'`); n != 0 {
		t.Fatalf("%d automatic transitions by the stopped gateway", n)
	}

	e.Start(gatewaytest.Binaries.Plain)
	s := e.Status()
	if s.Revision != 1 || s.Provisional != 0 || len(s.Overrides) != 0 || s.Admission != "ready" {
		t.Fatalf("after the restart %+v", s)
	}
	if code, _ := e.Get("/a/x", gatewaytest.Bearer(t, "carol")...); code != http.StatusForbidden {
		t.Fatalf("carol after the restart: %d", code)
	}
	if code, _ := e.Get("/b/x", gatewaytest.Bearer(t, "bob")...); code != http.StatusOK {
		t.Fatalf("the expired override still applies: %d", code)
	}
	gatewaytest.Interrupt(t, e.Process)
	if code := e.WaitExit(); code != gatewaytest.ExitStopped {
		t.Fatalf("exit status %d after the restart\n%s", code, e.Output)
	}
	for _, id := range []string{fmt.Sprintf("auto-rollback:%d", activated.Provisional), fmt.Sprintf("auto-expire:%d", override.Override)} {
		if n := gatewaytest.QueryInt(t, e.Database, `SELECT count(*) FROM transition WHERE id = ? AND outcome = 'committed' AND audited_at IS NOT NULL`, id); n != 1 {
			t.Fatalf("%s: %d audited transitions, want 1", id, n)
		}
	}
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT count(*) FROM transition WHERE outcome = 'committed' AND audited_at IS NULL`); n != 0 {
		t.Fatalf("%d committed transitions without their audit record", n)
	}

	files, _ := filepath.Glob(e.AuditLog + "*")
	records := 0
	for _, file := range files {
		for _, ev := range gatewaytest.AuditLines(t, file) {
			records++
			if ev.Kind == "audit.recovered" {
				t.Fatalf("incomplete record in %s", filepath.Base(file))
			}
		}
	}
	if len(files) < 3 {
		t.Fatalf("%d audit files; the rotation was not exercised", len(files))
	}
	t.Logf("%d audit files, %d records", len(files), records)
}

// An abrupt kill is not a graceful stop: it drains nothing and claims
// nothing. Events still queued are absent after the restart, no loss count
// is invented for them, and no record is incomplete, because every write is
// whole.
func TestNativeKillMakesNoDrainClaim(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_AUDIT_HOLD="+filepath.Join(e.Dir, "audit-hold"))
	_, held := holdWriter(e)
	ids := append([]string{held}, refuse(e, 20)...)
	e.Stop()
	output := e.Output.String()
	for _, claim := range []string{"draining", `"msg":"stopped"`, "stop incomplete"} {
		if strings.Contains(output, claim) {
			t.Fatalf("a killed process reported %q\n%s", claim, output)
		}
	}
	e.Start(gatewaytest.Binaries.Plain)
	events := e.AuditEvents()
	recorded := rejectedIDs(events)
	for _, id := range ids {
		if recorded[id] != 0 {
			t.Fatalf("request %s recorded after the kill", id)
		}
	}
	if lossOf(events) != 0 || gatewaytest.CountKind(events, "audit.recovered") != 0 {
		t.Fatalf("after the kill: loss %d, recovered %d", lossOf(events), gatewaytest.CountKind(events, "audit.recovered"))
	}
}

// An interrupt (Ctrl+Break on Windows) stops the gateway through its graceful
// path: the process exits with status 0, both listeners close, the audit file
// ends with a complete record, and the next start serves the same generation
// without finding an incomplete record. Every admission, which waits for its
// durable record, is in the file, and so is every outcome and refusal event,
// queued without acknowledgement, because the stop drains the queue.
func TestInterruptStopsGatewayGracefully(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Interruptible = true
	e.Start(gatewaytest.Binaries.Plain)
	generation := e.Status().Generation
	for range 3 {
		if code, _ := e.Get("/a/x"); code != http.StatusOK {
			t.Fatalf("admitted request: %d", code)
		}
		if code, _ := e.Get("/d"); code != http.StatusForbidden {
			t.Fatalf("denied request: %d", code)
		}
	}

	gatewaytest.Interrupt(t, e.Process)
	if code := e.WaitExit(); code != 0 {
		t.Fatalf("exit status %d after the interrupt\n%s", code, e.Output)
	}
	if gatewaytest.Dialable(e.DataAddr) || gatewaytest.Dialable(e.Admin) {
		t.Fatal("a listener still accepts connections after the gateway exited")
	}
	data, err := os.ReadFile(e.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatal("the audit file does not end with a complete record")
	}
	events := e.AuditEvents()
	for kind, want := range map[string]int{"request.admitted": 3, "request.forwarded": 3, "request.rejected": 3} {
		if n := gatewaytest.CountKind(events, kind); n != want {
			t.Fatalf("%d %s records in the audit file, want %d", n, kind, want)
		}
	}

	e.Interruptible = false
	e.Start(gatewaytest.Binaries.Plain)
	if s := e.Status(); s.Generation != generation {
		t.Fatalf("generation %s after the restart, want %s", s.Generation, generation)
	}
	events = e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "controller.reconciled") >= 2 })
	if gatewaytest.CountKind(events, "controller.reconciled") != 2 || gatewaytest.CountKind(events, "audit.recovered") != 0 {
		t.Fatalf("restart events: %d reconciled, %d recovered", gatewaytest.CountKind(events, "controller.reconciled"), gatewaytest.CountKind(events, "audit.recovered"))
	}
}
