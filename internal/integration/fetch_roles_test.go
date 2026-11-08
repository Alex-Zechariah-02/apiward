// Fetch roles taken only from verified tokens.

package integration

import (
	"slices"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
)

func TestFetchRolesOnlyFromVerifiedToken(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	for _, tc := range []struct {
		subject   string
		roles     any
		status    int
		forwarded string
	}{
		{"alice", nil, 403, ""},
		{"outside-policy-membership", []string{"WRITER", "UNKNOWN"}, 200, "WRITER"},
		{"alice", []string{"READER"}, 403, ""},
		{"bob", []string{"WRITER", "READER", "WRITER"}, 200, "READER,WRITER"},
		{"outside-policy-membership", []string{"UNKNOWN"}, 403, ""},
	} {
		claims := issuertest.Changed(issuertest.ValidClaims(tc.subject), map[string]any{"roles": tc.roles})
		resp, body := e.Exchange("POST", "/a/item", "application/json", `{"n":1}`, "Authorization", "Bearer "+gatewaytest.Issuer.Token(t, claims), "X-Gateway-Roles", "WRITER")
		if resp.StatusCode != tc.status {
			t.Errorf("%s %v: %d %s", tc.subject, tc.roles, resp.StatusCode, body)
			continue
		}
		if tc.status == 200 {
			receipts := e.A.Receipts()
			if receipts[len(receipts)-1].Headers.Get("X-Gateway-Roles") != tc.forwarded {
				t.Errorf("forwarded roles: %+v", receipts[len(receipts)-1])
			}
		}
	}
	e.AssertReceipts(2, 0, 0)
	droppedUnknown := func(events []map[string]any) bool {
		for _, event := range events {
			roles, _ := event["ignored_roles"].([]any)
			if event["subject"] == "outside-policy-membership" && slices.Contains(roles, any("UNKNOWN")) {
				return true
			}
		}
		return false
	}
	if !droppedUnknown(e.EventsWhen(droppedUnknown)) {
		t.Fatal("the dropped UNKNOWN role was not recorded")
	}
}
