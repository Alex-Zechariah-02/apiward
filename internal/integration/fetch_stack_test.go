// The Fetch demo stack end to end: account sign-in, service calls through the
// gateway, temporary grants and containment, policy changes, blocks and the
// demo command line, each proven by the services' own receipts.

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// This test shares the gateway integration package's serial process harness so
// its fixed offset ports cannot collide with TestNativeDemoCommands.
func TestFetchStackScenarios(t *testing.T) {
	s := startFetchStack(t)
	e, dir, root, baseline, revision, password := s.e, s.dir, s.root, s.baseline, s.revision, s.password
	parent := filepath.Dir(dir) // holds the stack's state and web directories
	call, login, control, receiptCount, refused, loadPolicy := s.call, s.login, s.control, s.receiptCount, s.refused, s.loadPolicy
	customer, merchant, rider, support, ops := login("customer1@fetch.test"), login("merchant1@fetch.test"), login("rider1@fetch.test"), login("support1@fetch.test"), login("admin1@fetch.test")
	seedHashes := make([]string, 5)
	for i := range seedHashes {
		var state stackState
		if json.Unmarshal(control(i, "/state"), &state) != nil {
			t.Fatal("invalid state")
		}
		seedHashes[i] = state.SHA256
	}
	cli := func(credential bool, args ...string) string {
		t.Helper()
		command := exec.Command(gatewaytest.Binaries.Demo, args...)
		if credential {
			command.Stdin = strings.NewReader(password + "\n")
		}
		data, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("demo %s: %v (%s)", args[0], err, data)
		}
		return string(data)
	}

	t.Log("the shop reached only through its public website operations")
	s.website()

	t.Log("real customer, merchant and rider flow")
	call("GET", "/inventory/categories", "", "", 200)
	call("GET", "/inventory/search?q=nasi", "", "", 200)
	call("GET", "/orders/quote?merchant=MER-001", "", customer, 200)
	checkout := `{"merchant":"MER-001","items":[{"item":"ITM-001","quantity":2},{"item":"ITM-004","quantity":1}],"address":{"line1":"12 Jalan Telawi 3","postcode":"59100","city":"Kuala Lumpur","state":"Wilayah Persekutuan Kuala Lumpur"},"payment":"cash"}`
	response, created := e.Exchange("POST", "/orders", "application/json", checkout, "Authorization", "Bearer "+customer, "Idempotency-Key", "fetch-stack-checkout")
	if response.StatusCode != 201 {
		t.Fatalf("checkout: %d %s", response.StatusCode, created)
	}
	var order struct {
		Order stackOrder `json:"order"`
	}
	if json.Unmarshal([]byte(created), &order) != nil || order.Order.ID != "ORD-1005" || order.Order.Total != 3329 {
		t.Fatalf("incorrect priced checkout: %s", created)
	}
	for _, action := range []struct{ path, token string }{{"accept", merchant}, {"ready", merchant}, {"pickup", rider}, {"deliver", rider}} {
		call("POST", "/orders/"+action.path+"/ORD-1005", "", action.token, 200)
	}
	call("GET", "/orders/detail/ORD-1005", "", customer, 200)
	call("GET", "/reports/summary?from=2026-08-01&to=2099-12-31", "", ops, 200)
	for _, path := range []string{"/accounts/me", "/accounts/refresh"} {
		method := "GET"
		if strings.HasSuffix(path, "refresh") {
			method = "POST"
		}
		call(method, path, "", customer, 200)
	}

	t.Log("gateway refusals never reach services")
	before := receiptCount(0)
	refusal, _ := call("PATCH", "/inventory/items/ITM-001", `{"price_sen":1400}`, support, 403)
	ref := refusal.Header.Get("X-Request-Id")
	if receiptCount(0) != before || refusal.Header.Get("X-Service") != "" {
		t.Fatal("support edit reached Inventory")
	}
	before = receiptCount(1)
	validationCustomer := login("customer3@fetch.test")
	for _, invalid := range []string{
		`{"merchant":"MER-001","items":[]}`,
		strings.Replace(checkout, `"quantity":2`, `"quantity":0`, 1),
		strings.Replace(checkout, `"quantity":2`, `"quantity":51`, 1),
		strings.Replace(checkout, `"state":"Wilayah Persekutuan Kuala Lumpur"`, `"state":"Unknown"`, 1),
		strings.Replace(checkout, `"payment":"cash"`, `"payment":"cash","unexpected":1`, 1),
	} {
		call("POST", "/orders", invalid, validationCustomer, 400)
	}
	call("POST", "/orders", strings.Repeat(" ", 4096)+checkout, validationCustomer, 413)
	if receiptCount(1) != before {
		t.Fatal("invalid checkout reached Orders")
	}
	refused(1, "GET", "/internal/orders", "", ops, 404)

	t.Log("customer stock permission is controlled by a temporary gateway grant")
	before = receiptCount(0)
	call("GET", "/inventory/stock/ITM-501", "", customer, 403)
	if receiptCount(0) != before {
		t.Fatal("unpermitted stock read reached Inventory")
	}
	e.MustOverride(root, permitOverride(store.OverrideException, "CUSTOMER", "inventory.stock.read", 1), gatewaytest.RevisionTag(revision), "fetch-stack-stock-grant")
	call("GET", "/inventory/stock/ITM-501", "", customer, 200)
	if receiptCount(0) != before+1 {
		t.Fatal("temporary stock grant did not reach Inventory exactly once")
	}
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "temporary stock grant expiry", func() bool {
		response, _ := e.Exchange("GET", "/inventory/stock/ITM-501", "", "", "Authorization", "Bearer "+customer)
		return response.StatusCode == 403
	})

	t.Log("platform reports follow gateway grants; baseline and expiry still refuse")
	reportOperations := []struct{ id, path string }{{"reports.summary", "/reports/summary"}, {"reports.sales", "/reports/sales"}, {"reports.top-items", "/reports/top-items"}}
	before = receiptCount(2)
	for _, operation := range reportOperations {
		call("GET", operation.path, "", customer, 403)
	}
	if receiptCount(2) != before {
		t.Fatal("unpermitted report reached Reports")
	}
	for i, operation := range reportOperations {
		e.MustOverride(root, permitOverride(store.OverrideException, "CUSTOMER", operation.id, 5), gatewaytest.RevisionTag(revision), fmt.Sprintf("fetch-report-grant-%d", i))
	}
	for _, operation := range reportOperations {
		call("GET", operation.path, "", customer, 200)
	}
	if receiptCount(2) != before+3 {
		t.Fatal("gateway report grants did not forward each request exactly once")
	}
	gatewaytest.WaitFor(t, time.Now().Add(8*time.Second), "report grant expiry", func() bool { return len(activeOverrides(e, root).GenerationOverrides) == 0 })
	for _, operation := range reportOperations {
		call("GET", operation.path, "", customer, 403)
	}
	if receiptCount(2) != before+3 {
		t.Fatal("expired report grant reached Reports")
	}

	t.Log("real source-bound flood commands")
	floodCustomer := login("customer2@fetch.test")
	ordersBeforeFlood := receiptCount(1)
	for _, scenario := range []struct{ name, source, count string }{{"flood-orders", "127.0.0.51", "12"}, {"flood-search", "127.0.0.50", "65"}, {"flood-login", "127.0.0.52", "12"}} {
		result := cli(false, "attack", "-dir", dir, "-scenario", scenario.name, "-from", scenario.source, "-count", scenario.count)
		if !strings.Contains(result, "429:") || !strings.Contains(result, "from="+scenario.source) {
			t.Fatalf("flood did not demonstrate quota: %s", result)
		}
	}
	var floodReceipts struct {
		Receipts []stackReceipt `json:"receipts"`
	}
	if err := json.Unmarshal(control(1, "/receipts"), &floodReceipts); err != nil {
		t.Fatal(err)
	}
	flooded := floodReceipts.Receipts[ordersBeforeFlood:]
	if len(flooded) != 10 {
		t.Fatalf("order flood reached Orders %d times, want 10", len(flooded))
	}
	for _, receipt := range flooded {
		if receipt.Subject != "cust-002" || receipt.Status != 201 {
			t.Fatalf("order flood receipt: subject=%s status=%d", receipt.Subject, receipt.Status)
		}
	}
	refused(1, "POST", "/orders", checkout, floodCustomer, 429)
	call("POST", "/orders", checkout, customer, 201)
	if receiptCount(1) != ordersBeforeFlood+11 {
		t.Fatal("separate customer checkout did not reach Orders exactly once")
	}

	t.Log("containment applies, then expires")
	e.MustOverride(root, gatewaytest.OperationContainment("orders.create", 1), gatewaytest.RevisionTag(revision), "fetch-stack-contain")
	refused(1, "POST", "/orders", checkout, customer, 403)
	refused(1, "POST", "/orders", checkout, floodCustomer, 403)
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "containment expiry", func() bool {
		code, _ := e.Get("/orders/wallet", "Authorization", "Bearer "+customer)
		return code == 200 && len(activeOverrides(e, root).GenerationOverrides) == 0
	})
	// The old exhausted quota carries over; expiry removes only containment.
	refused(1, "POST", "/orders", checkout, floodCustomer, 429)

	t.Log("add a Support operation through complete policy activation")
	without := loadPolicy("baseline.json")
	without.Operations = slices.DeleteFunc(without.Operations, func(op policy.Operation) bool { return op.ID == "support.queue" })
	without.Permits = slices.DeleteFunc(without.Permits, func(p policy.Permit) bool { return p.Operation == "support.queue" })
	revision = confirmPolicy(e, root, without, revision, "fetch-stack-without-queue").Revision
	refused(3, "GET", "/support/queue", "", support, 404)
	revision = confirmPolicy(e, root, baseline, revision, "fetch-stack-add-queue").Revision
	call("GET", "/support/queue", "", support, 200)

	t.Log("impact predicts loss of rider access; unconfirmed activation rolls back")
	call("GET", "/orders/jobs", "", rider, 200)
	bad := loadPolicy("baseline.json")
	bad.Permits = slices.DeleteFunc(bad.Permits, func(p policy.Permit) bool { return p.Role == "RIDER" && p.Operation == "orders.jobs" })
	code, staged, body := e.Stage(root, bad, gatewaytest.RevisionTag(revision), "fetch-stack-bad-rider")
	if code != 201 {
		t.Fatalf("bad rider candidate: %d %s", code, body)
	}
	code, impact, _ := e.As(root, "POST", fmt.Sprintf("/admin/candidates/%d/impact", staged.Candidate.ID), "")
	if code != 200 || !strings.Contains(impact, `"operation":"orders.jobs"`) || !strings.Contains(impact, `"after":"refused"`) {
		t.Fatalf("impact missed real rider flip: %d %s", code, impact)
	}
	if code, _, body = e.Activate(root, staged.Candidate.CandidateRecord, 1, gatewaytest.RevisionTag(revision), "fetch-stack-bad-activate"); code != 200 {
		t.Fatalf("bad activation: %d %s", code, body)
	}
	refused(1, "GET", "/orders/jobs", "", rider, 403)
	gatewaytest.WaitFor(t, time.Now().Add(5*time.Second), "automatic rollback", func() bool { code, _ := e.Get("/orders/jobs", "Authorization", "Bearer "+rider); return code == 200 })

	t.Log("ticket reference resolves the exact refused decision")
	call("POST", "/support/tickets", string(gatewaytest.MustJSON(map[string]string{"subject": "Please inspect this refusal", "message": "The request reference is attached.", "request_ref": ref})), customer, 201)
	code, event, _ := e.As(root, "GET", "/admin/events?ref="+ref, "")
	if code != 200 || !strings.Contains(event, `"subject":"support-01"`) || !strings.Contains(event, `"stage":"permit"`) || !strings.Contains(event, `"code":"forbidden"`) {
		t.Fatalf("reference lookup: %d %s", code, event)
	}

	t.Log("blocking remains an independent immediate control")
	code, body, _ = e.As(root, "PUT", "/admin/blocked-accounts/cust-001", `{"reason":"isolated stack test"}`, "Idempotency-Key", "fetch-stack-block")
	if code != 200 {
		t.Fatalf("block: %d %s", code, body)
	}
	before = receiptCount(4)
	call("GET", "/accounts/me", "", customer, 403)
	if receiptCount(4) != before {
		t.Fatal("blocked account reached Accounts")
	}
	code, body, _ = e.As(root, "DELETE", "/admin/blocked-accounts/cust-001", "", "Idempotency-Key", "fetch-stack-unblock")
	if code != 200 {
		t.Fatalf("unblock: %d %s", code, body)
	}
	call("GET", "/accounts/me", "", customer, 200)

	t.Log("operator policy export/stage and overlapping signing-key rotation")
	exported := filepath.Join(parent, "exported.json")
	cli(true, "policy", "export", "-dir", dir, "-out", exported)
	exportedData, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.DecodePolicy(exportedData); err != nil {
		t.Fatal(err)
	}
	if result := cli(true, "policy", "stage", "-dir", dir, "-file", exported); !strings.Contains(result, "not activated") {
		t.Fatal("stage silently activated")
	}
	cli(true, "keys", "rotate", "-dir", dir)
	call("GET", "/accounts/me", "", customer, 200)
	_, refreshed := call("POST", "/accounts/refresh", "", customer, 200)
	var newToken struct {
		Token string `json:"token"`
	}
	if json.Unmarshal([]byte(refreshed), &newToken) != nil || newToken.Token == "" {
		t.Fatal("refresh after rotation failed")
	}
	call("GET", "/accounts/me", "", newToken.Token, 200)
	cli(true, "keys", "retire", "-dir", dir, "-kid", "fetch-2026-10-a")
	call("GET", "/accounts/me", "", customer, 401)
	call("GET", "/accounts/me", "", newToken.Token, 200)
	cli(false, "reset", "-dir", dir)
	for i, want := range seedHashes {
		var state stackState
		if json.Unmarshal(control(i, "/state"), &state) != nil || state.SHA256 != want {
			t.Fatalf("service %d seed hash changed after reset", i)
		}
		if receiptCount(i) != 0 {
			t.Fatalf("service %d reset retained receipts", i)
		}
	}
	assertAbsent(t, e, customer, merchant, rider, support, ops, newToken.Token, "FetchDemo2026!", password)
	s.input.Close()
	select {
	case err := <-s.exited:
		if err != nil {
			t.Fatalf("stack shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("stack did not stop")
	}
	for _, base := range []int{9440, 9450, 9480, 9501, 9502, 9503, 9504, 9505, 9601, 9602, 9603, 9604, 9605} {
		host := "127.0.0.1"
		if base == 9480 {
			host = "127.0.0.2"
		}
		if gatewaytest.Dialable(gatewaytest.DemoTestAddress(t, fmt.Sprintf("%s:%d", host, base))) {
			t.Fatalf("stack leaked port %d", base)
		}
	}
}
