// Durable audit before admission, and admission stopped when audit fails.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// An admission is forwarded only after its record is durable: when the sync
// does not complete within the acknowledgement wait, or the process dies
// between write and sync, nothing is forwarded, and a record written but not
// acknowledged is never followed by a forwarded outcome.
func TestAdmissionWaitsForDurableAudit(t *testing.T) {
	t.Parallel()
	t.Run("sync slower than the acknowledgement wait", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		e.WriteConfig(gatewaytest.ConfigOptions{Audit: map[string]any{"audit_timeout": "1s"}})
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-slow-sync")

		started := time.Now()
		resp, body := e.Exchange(http.MethodGet, "/a/x", "", "")
		_, id := gatewaytest.RequestID(resp, body)
		if resp.StatusCode != http.StatusServiceUnavailable || time.Since(started) > 2500*time.Millisecond {
			t.Fatalf("slow sync: %d after %v", resp.StatusCode, time.Since(started))
		}
		e.AssertReceipts(0, 0, 0)
		// The admission record becomes durable later; it is followed by the
		// AUDIT rejection, never by a forwarded outcome. The writer is still
		// in its delayed sync, so the rejection lands a few seconds later.
		var events []map[string]any
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			events = nil
			for _, ev := range e.AuditEvents() {
				if ev["request_id"] == id {
					events = append(events, ev)
				}
			}
			if len(events) >= 2 {
				break
			}
		}
		if len(events) != 2 || events[0]["kind"] != "request.admitted" || events[1]["kind"] != "request.rejected" || events[1]["stage"] != "AUDIT" {
			t.Fatalf("events %v", events)
		}
		if gatewaytest.FindEvent(e.AuditEvents(), "request.forwarded", id) != nil {
			t.Fatal("an unacknowledged admission has a forwarded outcome")
		}
	})

	t.Run("process dies between write and sync", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-crash-before-sync")

		req, _ := http.NewRequest(http.MethodGet, "http://"+e.DataAddr+"/a/x", http.NoBody)
		if resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req); err == nil {
			resp.Body.Close()
			t.Fatalf("request answered %d by a process that should have stopped", resp.StatusCode)
		}
		if code := e.WaitExit(); code != crashExit {
			t.Fatalf("exit code %d", code)
		}
		e.AssertReceipts(0, 0, 0)

		// After a restart the written record may be present, but nothing
		// claims it was forwarded, and admission works again.
		e.Start(gatewaytest.Binaries.Plain)
		if code, _ := e.Get("/a/x"); code != http.StatusOK {
			t.Fatalf("after restart: %d", code)
		}
		records := auditRecords(e)
		admitted, forwarded := gatewaytest.CountKind(records, "request.admitted"), gatewaytest.CountKind(records, "request.forwarded")
		if admitted != 2 || forwarded != 1 {
			t.Fatalf("after the crash and one forwarded request: %d admitted, %d forwarded records", admitted, forwarded)
		}
		e.AssertReceipts(1, 0, 0)
	})
}

// A failure to record an outcome after the upstream acted cannot undo that
// action: the fixture change stays and the log shows the admission without
// an outcome. The failed file is replaced without a restart: the replacement is recorded with the lost outcome counted, and
// once the failure has passed, later requests are admitted again.
func TestOutcomeFailureStopsLaterAdmissions(t *testing.T) {
	t.Parallel()
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, gatewaytest.FixturePolicy(fixtures), gatewaytest.SeedOptions{})
	armed := filepath.Join(e.Dir, "fault-armed")
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-fail-outcome", "GATEWAY_FAULT_ARMED="+armed)
	e.Status() // signs the harness in while the log still works
	if err := os.WriteFile(armed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	orders := fixtures["orders"]
	seedState := orders.State().SHA256

	resp, body := e.Exchange(http.MethodPost, "/orders", "application/json", `{"customer":"cust-001","item":"ITM-001","quantity":1}`, gatewaytest.Bearer(t, "cust-001")...)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first order: %d %s", resp.StatusCode, body)
	}
	id := orders.Receipts()[0].RequestID
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "the outcome failure", func() bool {
		return strings.Contains(e.Output.String(), "audit file failed; replacing it")
	})
	if orders.State().SHA256 == seedState || len(orders.Receipts()) != 1 {
		t.Fatal("the forwarded order did not take effect")
	}
	os.Remove(armed)
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "admission again", func() bool {
		code, _ := e.Request(http.MethodGet, "/inventory/health", "", "", gatewaytest.Bearer(t, "staff-01")...)
		return code == http.StatusOK
	})
	if code, _ := e.Get("/orders"); code != http.StatusUnauthorized {
		t.Errorf("a refusal stays a refusal: %d", code)
	}
	events := e.AuditEvents()
	if gatewaytest.FindEvent(events, "request.admitted", id) != nil || gatewaytest.FindEvent(events, "request.forwarded", id) != nil {
		t.Fatalf("the new file holds records of %s", id)
	}
	recovered, lost := false, 0.0
	for _, ev := range events {
		recovered = recovered || (ev["kind"] == "audit.recovered" && ev["reason"] == "sync_failed")
		if ev["kind"] == "audit.loss" {
			lost += ev["lost"].(float64)
		}
	}
	if !recovered || lost < 1 {
		t.Fatalf("replacement recorded %v, lost outcomes counted %v", recovered, lost)
	}
	var admitted bool
	for _, file := range gatewaytest.RotatedAudit(t, e.AuditLog) {
		if found, _ := gatewaytest.ParseAudit(gatewaytest.ReadAudit(t, file), filepath.Base(file)); gatewaytest.FindEvent(found, "request.admitted", id) != nil {
			admitted = gatewaytest.FindEvent(found, "request.forwarded", id) == nil
		}
	}
	if !admitted {
		t.Fatalf("the replaced file does not show %s admitted without an outcome", id)
	}
}

// With the fixtures behind the gateway, an audit sink that cannot make a
// record durable still stops every admission before forwarding, even for a
// request that passed authentication and authorisation.
func TestAuditFailureBlocksFixtureForwarding(t *testing.T) {
	t.Parallel()
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, gatewaytest.FixturePolicy(fixtures), gatewaytest.SeedOptions{})
	e.StartFailingAudit("audit-sync")

	c := gatewaytest.LoadCatalogue(t)
	for _, sc := range c.Scenarios {
		contentType := ""
		if len(sc.Body) > 0 {
			contentType = "application/json"
		}
		var header []string
		if sc.Subject != "" {
			header = gatewaytest.Bearer(t, sc.Subject)
		}
		// A step refused by validation never reaches the audit gate, so it
		// keeps its own refusal.
		want := http.StatusServiceUnavailable
		if sc.GatewayStage != "" {
			want = sc.GatewayStatus
		}
		if code, _ := e.Request(sc.Method, sc.Path, contentType, string(sc.Body), header...); code != want {
			t.Errorf("%s with a failed audit sink: %d, want %d", sc.Name, code, want)
		}
	}
	for name, n := range gatewaytest.ReceiptCounts(fixtures) {
		if n != 0 {
			t.Errorf("fixture %s received %d requests while the audit sink was failing", name, n)
		}
	}
	if s := e.Status(); !s.AuditFailed {
		t.Fatalf("status %+v does not report the audit failure", s)
	}
}
