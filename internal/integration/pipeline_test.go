// The five controls on one request path: admission, early refusals, refusals
// during publication, forged control headers and upstream failure.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// allStages is the stage map of a request that passed every control and was
// forwarded.
func allStages() map[string]any {
	stages := map[string]any{}
	for _, name := range audit.StageNames {
		stages[name] = audit.StagePass
	}
	return stages
}

// A valid request passes all five controls on one request path, under one
// generation, and the intended fixture performs the operation: the event
// chain, the receipt and the state change agree.
func TestFiveControlsAdmitValidRequest(t *testing.T) {
	e, fixtures := newFixtureEnv(t)
	g := e.Status().Generation
	orders, inventory := fixtures["orders"], fixtures["inventory"]

	requests := []struct {
		subject, method, path, body, fixture, effect string
		status                                       int
	}{
		{"cust-002", "POST", "/orders", `{"customer":"cust-002","item":"ITM-003","quantity":4}`, "orders", "created ORD-1004", 201},
		{"staff-01", "PATCH", "/inventory/items/ITM-002", `{"delta":5}`, "inventory", "ITM-002 stock 15->20", 200},
	}
	for _, r := range requests {
		target := fixtures[r.fixture]
		before := target.State().SHA256
		resp, body := e.Exchange(r.method, r.path, "application/json", r.body, gatewaytest.Bearer(t, r.subject)...)
		if resp.StatusCode != r.status || resp.Header.Get("X-Service") != r.fixture {
			t.Fatalf("%s %s: %d from %q (%s)", r.method, r.path, resp.StatusCode, resp.Header.Get("X-Service"), body)
		}
		receipts := target.Receipts()
		receipt := receipts[len(receipts)-1]
		if receipt.Effect != r.effect || target.State().SHA256 == before || receipt.Generation != g ||
			receipt.Subject != r.subject || receipt.Authorization || receipt.BodySHA256 != sha256Hex(r.body) {
			t.Fatalf("%s: receipt %+v", r.path, receipt)
		}
		events := e.RequestEvents(receipt.RequestID, 2)
		admitted, forwarded := gatewaytest.FindEvent(events, "request.admitted", receipt.RequestID), gatewaytest.FindEvent(events, "request.forwarded", receipt.RequestID)
		wantAdmitted := allStages()
		wantAdmitted["AUDIT"], wantAdmitted["BIND"], wantAdmitted["FORWARD"] = audit.StageNotRun, audit.StageNotRun, audit.StageNotRun
		if admitted == nil || forwarded == nil || !gatewaytest.SameStages(admitted["stages"], wantAdmitted) || !gatewaytest.SameStages(forwarded["stages"], allStages()) {
			t.Fatalf("%s: events %v", r.path, events)
		}
		for _, ev := range events {
			if ev["generation"] != g || ev["subject"] != r.subject || ev["operation"] != receipt.Operation {
				t.Fatalf("%s: event %v disagrees with the receipt %+v", r.path, ev, receipt)
			}
		}
	}
	if n := len(fixtures["reports"].Receipts()); n != 0 || len(orders.Receipts()) != 1 || len(inventory.Receipts()) != 1 {
		t.Fatalf("receipts: orders %d inventory %d reports %d", len(orders.Receipts()), len(inventory.Receipts()), n)
	}
}

// fixtureWithRate is the fixture policy with another rate rule on
// orders.create and, when schema is set, another body schema.
func fixtureWithRate(fixtures map[string]*gatewaytest.FixtureProcess, r *policy.RateRule, schema string) policy.Policy {
	p := gatewaytest.FixturePolicy(fixtures)
	for i := range p.Operations {
		if p.Operations[i].ID == "orders.create" {
			p.Operations[i].Rate = r
			if schema != "" {
				p.Operations[i].Body = gatewaytest.JSONBody(1024, schema)
			}
		}
	}
	return p
}

// An early refusal stops the path: a JWT or RBAC refusal consumes no quota
// and evaluates no body, and a rate refusal of an otherwise valid request
// evaluates no body; none reaches a fixture.
func TestEarlyRefusalsStopThePath(t *testing.T) {
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, fixtureWithRate(fixtures, gatewaytest.Rate(2, 60), ""), gatewaytest.SeedOptions{})
	clock := newControlledClock(t, base)
	e.Start(gatewaytest.Binaries.Fault, clock.env())

	valid := `{"customer":"cust-001","item":"ITM-001","quantity":1}`
	routed := []string{"INGRESS", "CAPTURE", "CANONICAL", "ROUTE", "ACCESS"}
	cases := []struct {
		name, body string
		header     []string
		status     int
		want       map[string]any
	}{
		{"forged token", valid, []string{"Authorization", "Bearer " + issuertest.New(2048).TokenFor(t, "cust-001")}, 401, gatewaytest.ExpectedStages(routed, "JWT", audit.StageReject)},
		{"wrong role", valid, gatewaytest.Bearer(t, "staff-01"), 403, gatewaytest.ExpectedStages(append(slices.Clone(routed), "JWT"), "RBAC", audit.StageReject)},
		{"wrong role with an invalid body", `{"x":`, gatewaytest.Bearer(t, "mgr-01"), 403, gatewaytest.ExpectedStages(append(slices.Clone(routed), "JWT"), "RBAC", audit.StageReject)},
		{"first admitted", valid, gatewaytest.Bearer(t, "cust-001"), 201, nil},
		{"second admitted", valid, gatewaytest.Bearer(t, "cust-001"), 201, nil},
		{"first excess with a valid body", valid, gatewaytest.Bearer(t, "cust-001"), 429, gatewaytest.ExpectedStages(append(slices.Clone(routed), "JWT", "RBAC"), "RATE", audit.StageReject)},
		{"excess with an invalid body", `{"x":`, gatewaytest.Bearer(t, "cust-001"), 429, gatewaytest.ExpectedStages(append(slices.Clone(routed), "JWT", "RBAC"), "RATE", audit.StageReject)},
	}
	for _, tc := range cases {
		resp, body := e.Exchange(http.MethodPost, "/orders", "application/json", tc.body, tc.header...)
		if resp.StatusCode != tc.status {
			t.Fatalf("%s: %d %s", tc.name, resp.StatusCode, body)
		}
		if tc.want == nil {
			continue
		}
		_, id := gatewaytest.RequestID(resp, body)
		events := e.RequestEvents(id, 1)
		if len(events) != 1 || !gatewaytest.SameStages(events[0]["stages"], tc.want) {
			t.Fatalf("%s: events %v, want stages %v", tc.name, events, tc.want)
		}
	}
	if counts := gatewaytest.ReceiptCounts(fixtures); counts["orders"] != 2 || counts["inventory"] != 0 || counts["reports"] != 0 {
		t.Fatalf("receipts %v, want the two admitted orders only", counts)
	}
}

// A request refused by validation while another generation is published is
// decided entirely by the generation it captured: its schema refuses it, its
// rate rule counted it, and the event names that generation. Nothing is
// forwarded.
func TestValidationRefusalDuringPublication(t *testing.T) {
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	strict := `{"type":"object","additionalProperties":false,"required":["customer","item","quantity"],"properties":{` +
		`"customer":{"type":"string"},"item":{"type":"string"},"quantity":{"type":"integer","maximum":1}}}`
	gatewaytest.Seed(t, e.Database, fixtureWithRate(fixtures, gatewaytest.Rate(2, 60), strict), gatewaytest.SeedOptions{})
	clock := newControlledClock(t, base)
	dir := t.TempDir()
	holdFile, release := filepath.Join(dir, "captured"), filepath.Join(dir, "release")
	e.Start(gatewaytest.Binaries.Fault, clock.env(), "GATEWAY_HOLD_PATH=/orders", "GATEWAY_HOLD_FILE="+holdFile, "GATEWAY_HOLD_RELEASE="+release)
	first := e.Status().Generation

	// Under the first generation a quantity of 2 is refused; under the
	// second, the fixture schema, it is allowed. The held request carries it.
	extra := `{"customer":"cust-001","item":"ITM-001","quantity":2}`
	type reply struct {
		status int
		body   string
	}
	result := make(chan reply, 1)
	go func() {
		status, body := e.Request(http.MethodPost, "/orders", "application/json", extra, gatewaytest.Bearer(t, "cust-001")...)
		result <- reply{status, body}
	}()
	waitForFile(t, holdFile)
	outcome, code := e.Publish(controller.Change{ID: "fixture-schema", Expected: 1, Policy: gatewaytest.MustJSON(fixtureWithRate(fixtures, gatewaytest.Rate(2, 60), gatewaytest.OrdersCreateSchema))})
	if code != http.StatusOK {
		t.Fatalf("publish: %d %+v", code, outcome)
	}
	os.WriteFile(release, nil, 0o600)
	held := <-result
	if held.status != http.StatusBadRequest {
		t.Fatalf("held request: %d %s", held.status, held.body)
	}
	_, id := gatewaytest.RequestID(&http.Response{}, held.body)
	ev := e.RequestEvents(id, 1)
	if len(ev) != 1 || ev[0]["stage"] != "VALIDATION" || ev[0]["generation"] != first || stagesOf(ev[0])["RATE"] != audit.StagePass {
		t.Fatalf("held request event %v, want a VALIDATION refusal under %s after RATE passed", ev, first)
	}
	// The refused request counted: one more admission fits, then 429.
	statuses := sendAs(e, "cust-001", http.MethodPost, "/orders", extra, 2)
	if !statusesAre(statuses, 201, 429) {
		t.Fatalf("after the refused request: %v, want 201 429", statuses)
	}
	receipts := fixtures["orders"].Receipts()
	if len(receipts) != 1 || receipts[0].Generation != outcome.Generation {
		t.Fatalf("receipts %+v, want one under %s", receipts, outcome.Generation)
	}
}

// Client-supplied stage, policy, rate and audit headers never skip a control.
// The refused invalid body still counts against the quota of 2, since it was
// admitted by the rate stage.
func TestForgedControlHeadersSkipNothing(t *testing.T) {
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, fixtureWithRate(fixtures, gatewaytest.Rate(2, 60), ""), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	forged := []string{
		"X-Gateway-Generation", "r1-forged", "X-Gateway-Validated", "true", "X-Gateway-Stage", "FORWARD",
		"X-Gateway-Rate", "exempt", "X-Gateway-Audit", "durable", "X-Request-Id", "forged", "X-Gateway-Subject", "staff-01",
		"X-Gateway-Roles", "STAFF,MANAGER", "X-Forwarded-For", "127.0.0.1",
	}
	invalid := `{"customer":"cust-001","item":"ITM-001","quantity":"many"}`
	if code, _ := e.Request(http.MethodPost, "/orders", "application/json", invalid, append(gatewaytest.Bearer(t, "cust-001"), forged...)...); code != http.StatusBadRequest {
		t.Fatalf("invalid body with forged headers: %d", code)
	}
	valid := `{"customer":"cust-001","item":"ITM-001","quantity":1}`
	if got := sendAs(e, "cust-001", http.MethodPost, "/orders", valid, 2, forged...); !statusesAre(got, 201, 429) {
		t.Fatalf("quota with forged headers: %v", got)
	}
	if code, _ := e.Request(http.MethodGet, "/reports/sales", "", "", append(gatewaytest.Bearer(t, "cust-001"), forged...)...); code != http.StatusForbidden {
		t.Fatalf("role escalation by header: %d", code)
	}
	if code, _ := e.Request(http.MethodGet, "/orders", "", "", forged...); code != http.StatusUnauthorized {
		t.Fatalf("no token with forged headers: %d", code)
	}
	receipts := fixtures["orders"].Receipts()
	if len(receipts) != 1 || receipts[0].Subject != "cust-001" || receipts[0].Roles != "CUSTOMER" || receipts[0].RequestID == "forged" ||
		receipts[0].Generation != e.Status().Generation {
		t.Fatalf("receipts %+v", receipts)
	}
}

// With every control in place, an unavailable upstream answers a safe error
// for concurrent valid requests, reaches no other destination, and records
// each outcome; rate and validation still apply.
func TestUpstreamFailureUnderFiveControls(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := ratePolicy(e, gatewaytest.Rate(30, 60), nil)
	p.Upstreams = append(p.Upstreams, policy.Upstream{ID: "Z", Dial: gatewaytest.FreeAddr(t)})
	p.APIs = append(p.APIs, policy.API{ID: "z", Upstream: "Z"})
	p.Operations = append(p.Operations, policy.Operation{ID: "write-z", API: "z", Method: "POST", Target: "/z", Access: "allow", Auth: "required",
		Body: gatewaytest.JSONBody(1024, `{"type":"object","additionalProperties":false,"required":["n"],"properties":{"n":{"type":"integer"}}}`), Rate: gatewaytest.Rate(20, 60)})
	p.Permits = append(p.Permits, policy.Permit{Role: "WRITER", Operation: "write-z"})
	gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	var wg sync.WaitGroup
	var mu sync.Mutex
	statuses := map[int]int{}
	token := gatewaytest.Issuer.TokenFor(t, "alice")
	for i := range 25 {
		wg.Go(func() {
			body := `{"n":1}`
			if i%5 == 0 {
				body = `{"n":"x"}`
			}
			req, _ := http.NewRequest(http.MethodPost, "http://"+e.DataAddr+"/z", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			mu.Lock()
			statuses[resp.StatusCode]++
			mu.Unlock()
		})
	}
	wg.Wait()
	// 25 requests, quota 20: 20 pass RATE (some with invalid bodies), 5 are
	// refused 429. Of those 20, the invalid ones are refused 400 and the
	// valid ones meet the closed port: 502.
	if statuses[http.StatusTooManyRequests] != 5 || statuses[http.StatusBadRequest]+statuses[http.StatusBadGateway] != 20 || statuses[http.StatusOK] != 0 {
		t.Fatalf("statuses %v", statuses)
	}
	e.AssertReceipts(0, 0, 0)
	events := e.EventsWhen(func(events []map[string]any) bool {
		return gatewaytest.CountKind(events, "request.forwarded") == statuses[http.StatusBadGateway]
	})
	failed := 0
	for _, ev := range events {
		if ev["kind"] == "request.forwarded" {
			if ev["decision"] != "upstream_failure" || ev["error"] != "upstream_unavailable" || ev["upstream"] != "Z" || ev["subject"] != "alice" {
				t.Fatalf("outcome %v", ev)
			}
			failed++
		}
	}
	if failed != statuses[http.StatusBadGateway] || failed == 0 {
		t.Fatalf("%d upstream failure events for %d 502 replies", failed, statuses[http.StatusBadGateway])
	}
	t.Logf("statuses %v", statuses)
}
