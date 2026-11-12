// Authentication events and unrecorded credentials.

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
)

// Authentication and authorisation events record what actually ran, with the
// verified subject only after verification, and never a credential.
func TestAuthenticationEvents(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	g := e.Status().Generation

	routed := []string{"INGRESS", "CAPTURE", "CANONICAL", "ROUTE", "ACCESS"}
	type expected struct {
		kind, stage, reason, subject, errorCode string
		status                                  int
		stages                                  map[string]any
	}
	aliceToken := gatewaytest.Issuer.TokenFor(t, "alice")
	cases := []struct {
		name     string
		method   string
		path     string
		body     string
		token    string
		receipts int
		want     []expected
	}{
		{"no token", http.MethodGet, "/a/x", "", "", 0, []expected{
			{"request.rejected", "JWT", "missing_credential", "", "unauthenticated", 401, gatewaytest.ExpectedStages(routed, "JWT", audit.StageReject)},
		}},
		{"expired token", http.MethodGet, "/a/x", "", gatewaytest.Issuer.Token(t, issuertest.Changed(issuertest.ValidClaims("alice"), map[string]any{"exp": time.Now().Add(-time.Minute).Unix()})), 0, []expected{
			{"request.rejected", "JWT", "expired", "", "unauthenticated", 401, gatewaytest.ExpectedStages(routed, "JWT", audit.StageReject)},
		}},
		{"unknown subject", http.MethodGet, "/a/x", "", gatewaytest.Issuer.TokenFor(t, "mallory"), 0, []expected{
			{"request.rejected", "RBAC", "no_permit", "mallory", "forbidden", 403, gatewaytest.ExpectedStages(append(routed, "JWT"), "RBAC", audit.StageReject)},
		}},
		{"no permit", http.MethodPost, "/a/item", `{"n":1}`, gatewaytest.Issuer.TokenFor(t, "bob"), 0, []expected{
			{"request.rejected", "RBAC", "no_permit", "bob", "forbidden", 403, gatewaytest.ExpectedStages(append(routed, "JWT"), "RBAC", audit.StageReject)},
		}},
		{"permitted", http.MethodPost, "/a/item", `{"n":1}`, aliceToken, 1, []expected{
			{"request.admitted", "AUDIT", "", "alice", "", 0, unrated(gatewaytest.ExpectedStages(append(routed, "JWT", "RBAC", "BODY", "VALIDATION"), "", ""))},
			{"request.forwarded", "FORWARD", "", "alice", "", 200, nil},
		}},
		{"denied public operation", http.MethodGet, "/d", "", aliceToken, 0, []expected{
			{"request.rejected", "ACCESS", "", "", "forbidden", 403, gatewaytest.ExpectedStages(routed[:4], "ACCESS", audit.StageReject)},
		}},
	}
	for _, tc := range cases {
		e.ResetReceivers()
		var header []string
		if tc.token != "" {
			header = []string{"Authorization", "Bearer " + tc.token}
		}
		resp, body := e.Exchange(tc.method, tc.path, "application/json", tc.body, header...)
		id := ""
		if tc.receipts > 0 {
			id = e.A.Receipts()[0].RequestID
		} else {
			_, id = gatewaytest.RequestID(resp, body)
		}
		e.AssertReceipts(tc.receipts, 0, 0)

		events := e.RequestEvents(id, len(tc.want))
		if len(events) != len(tc.want) {
			t.Fatalf("%s: %d events, want %d: %v", tc.name, len(events), len(tc.want), events)
		}
		for i, want := range tc.want {
			ev := events[i]
			reason, _ := ev["reason"].(string)
			subject, _ := ev["subject"].(string)
			errorCode, _ := ev["error"].(string)
			status, _ := ev["status"].(float64)
			if ev["kind"] != want.kind || ev["stage"] != want.stage || reason != want.reason || subject != want.subject ||
				errorCode != want.errorCode || int(status) != want.status || ev["generation"] != g || ev["schema"] != float64(audit.EventSchema) {
				t.Errorf("%s: event %v, want %+v", tc.name, ev, want)
			}
			if !gatewaytest.SameStages(ev["stages"], want.stages) {
				t.Errorf("%s: stages %v, want %v", tc.name, ev["stages"], want.stages)
			}
		}
	}

	// The fixture-facing identity is the verified one.
	e.ResetReceivers()
	e.Request(http.MethodGet, "/a/x", "", "", "Authorization", "Bearer "+aliceToken, "X-Gateway-Subject", "bob", "X-Gateway-Roles", "ADMIN")
	h := e.A.Receipts()[0].Headers
	if h.Get("X-Gateway-Subject") != "alice" || h.Get("X-Gateway-Roles") != "WRITER" || h.Get("Authorization") != "" {
		t.Fatalf("forwarded identity headers %v", h)
	}
}

// No credential, key or token reaches the audit log, the gateway's own
// output or a client error, whatever the request carries.
func TestCredentialsNeverRecorded(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	valid := gatewaytest.Issuer.TokenFor(t, "alice")
	forged := issuertest.New(2048).TokenFor(t, "alice")
	multiline := gatewaytest.Issuer.SignRaw(`{"alg":"RS256","kid":"test-a"}`, `{"iss":"https://issuer.test","aud":"gateway.test","sub":"alice\n{\"kind\":\"forged\"}","exp":9999999999}`)
	privatePEM := "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASC-----END PRIVATE KEY-----"
	requests := [][]string{
		{"Authorization", "Bearer " + valid},
		{"Authorization", "Bearer " + forged},
		{"Authorization", "Bearer " + multiline},
		{"Authorization", "Basic " + privatePEM},
		{"Authorization", privatePEM},
	}
	var replies []string
	for _, header := range requests {
		_, body := e.Request(http.MethodGet, "/a/x?token="+valid[:40], "", "", header...)
		replies = append(replies, body)
	}
	e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "request.rejected") >= 4 })
	e.AssertReceipts(1, 0, 0)

	raw, err := os.ReadFile(e.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(audit.Content(raw))
	e.Stop()
	output := e.Output.String()
	signatures := []string{}
	for _, token := range []string{valid, forged, multiline} {
		signatures = append(signatures, token[strings.LastIndex(token, ".")+1:])
	}
	secrets := append([]string{"eyJ", "Bearer", "Basic", "PRIVATE KEY", "MIIEvQ", valid[:40]}, signatures...)
	for _, secret := range secrets {
		if strings.Contains(logged, secret) {
			t.Errorf("audit log contains %q", secret)
		}
		if strings.Contains(output, secret) {
			t.Errorf("gateway output contains %q", secret)
		}
		for _, reply := range replies {
			if strings.Contains(reply, secret) {
				t.Errorf("client reply %q contains %q", reply, secret)
			}
		}
	}
	for i, line := range strings.Split(strings.TrimSuffix(logged, "\n"), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil || ev["kind"] == "forged" {
			t.Fatalf("audit line %d is not one genuine record: %q", i, line)
		}
	}
}
