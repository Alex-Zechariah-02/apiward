// Durable audit before admission and recovered records.

package integration

import (
	"bytes"
	"encoding/json"
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

// An interrupted append leaves an incomplete last record. After a restart it
// is kept, terminated, and named by an audit.recovered event; complete
// records are unchanged and admission works again.
func TestIncompleteRecordIsRecovered(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	if code, _ := e.Get("/a/x"); code != http.StatusOK {
		t.Fatal(code)
	}
	e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "request.forwarded") == 1 })
	e.Stop()
	complete, _ := os.ReadFile(e.AuditLog)

	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-partial")
	if code, _ := e.Get("/a/x"); code != http.StatusServiceUnavailable {
		t.Fatalf("admission with a partial write: %d", code)
	}
	if !e.Status().AuditFailed {
		t.Fatal("partial write not reported")
	}
	e.Stop()
	partial, _ := os.ReadFile(e.AuditLog)
	if !bytes.HasPrefix(partial, complete) || len(partial) == len(complete) || partial[len(partial)-1] == '\n' {
		t.Fatalf("expected an incomplete record after %d complete bytes; file has %d bytes", len(complete), len(partial))
	}
	offset := bytes.LastIndexByte(partial, '\n') + 1

	e.Start(gatewaytest.Binaries.Plain)
	if code, _ := e.Get("/a/x"); code != http.StatusOK {
		t.Fatalf("after recovery: %d", code)
	}
	// The shared readers refuse any invalid line, so this one parses the file
	// itself and checks below that the interrupted record is the only one.
	var data []byte
	var marker map[string]any
	for deadline := time.Now().Add(5 * time.Second); marker == nil && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		data, _ = os.ReadFile(e.AuditLog)
		for line := range bytes.SplitSeq(data, []byte("\n")) {
			var ev map[string]any
			if json.Unmarshal(line, &ev) == nil && ev["kind"] == "audit.recovered" {
				marker = ev
			}
		}
	}
	if !bytes.HasPrefix(data, partial) {
		t.Fatal("recovery rewrote existing records")
	}
	if marker == nil || marker["offset"] != float64(offset) || marker["file"] != filepath.Base(e.AuditLog) {
		t.Fatalf("recovery event %v, want offset %d", marker, offset)
	}
	// The incomplete record is on its own line and is the only invalid one.
	invalid := 0
	for line := range bytes.SplitSeq(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		if !json.Valid(line) {
			invalid++
			if !bytes.Equal(line, partial[offset:]) {
				t.Fatalf("invalid line %q is not the interrupted record", line)
			}
		}
	}
	if invalid != 1 {
		t.Fatalf("%d invalid lines, want 1", invalid)
	}
	e.AssertReceipts(2, 0, 0)
}

// A failure to record an outcome after the upstream acted cannot undo that
// action: the fixture change stays, the log shows the admission without an
// outcome, the failure is reported, and no later request is admitted.
func TestOutcomeFailureStopsLaterAdmissions(t *testing.T) {
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, gatewaytest.FixturePolicy(fixtures), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-fail-outcome")
	orders := fixtures["orders"]
	seedState := orders.State().SHA256

	resp, body := e.Exchange(http.MethodPost, "/orders", "application/json", `{"customer":"cust-001","item":"ITM-001","quantity":1}`, gatewaytest.Bearer(t, "cust-001")...)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first order: %d %s", resp.StatusCode, body)
	}
	id := orders.Receipts()[0].RequestID
	deadline := time.Now().Add(5 * time.Second)
	for !e.Status().AuditFailed {
		if time.Now().After(deadline) {
			t.Fatal("outcome failure not reported")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if orders.State().SHA256 == seedState || len(orders.Receipts()) != 1 {
		t.Fatal("the forwarded order did not take effect")
	}
	for _, path := range []string{"/orders", "/inventory/health"} {
		if code, _ := e.Request(http.MethodGet, path, "", "", gatewaytest.Bearer(t, "staff-01")...); code != http.StatusServiceUnavailable {
			t.Errorf("GET %s after the outcome failure: %d, want 503", path, code)
		}
	}
	if code, _ := e.Get("/orders"); code != http.StatusUnauthorized {
		t.Errorf("a refusal stays a refusal: %d", code)
	}
	if n := len(orders.Receipts()); n != 1 {
		t.Fatalf("%d receipts after the failure, want 1", n)
	}
	events := e.AuditEvents()
	if gatewaytest.FindEvent(events, "request.admitted", id) == nil || gatewaytest.FindEvent(events, "request.forwarded", id) != nil {
		t.Fatalf("log for %s: admitted %v forwarded %v", id, gatewaytest.FindEvent(events, "request.admitted", id), gatewaytest.FindEvent(events, "request.forwarded", id))
	}
	if !strings.Contains(e.Output.String(), "audit log failed; protected admission disabled") {
		t.Fatalf("no operator diagnostic in\n%s", e.Output)
	}
}

// With the fixtures behind the gateway, an audit sink that cannot make a
// record durable still stops every admission before forwarding, even for a
// request that passed authentication and authorisation.
func TestAuditFailureBlocksFixtureForwarding(t *testing.T) {
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, gatewaytest.FixturePolicy(fixtures), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Fault, "GATEWAY_FAULT=audit-sync")

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
