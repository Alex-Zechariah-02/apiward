// A fixture write followed by a client disconnect: the write is observed and
// never replayed.

package integration

import (
	"bytes"
	"net/http"
	"os"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// Observe an actual committed fixture mutation independently of a lost
// acknowledgement, and prove that neither build silently replays it.
func TestNativeFixtureWriteThenDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		binary string
		status int
	}{
		{"normal excludes fault", gatewaytest.Binaries.Fixture, http.StatusCreated},
		{"fault build loses acknowledgement", gatewaytest.Binaries.FixtureFault, http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binary, err := os.ReadFile(tc.binary)
			if err != nil {
				t.Fatal(err)
			}
			if included := bytes.Contains(binary, []byte("FIXTURE_FAULT")); included != (tc.binary == gatewaytest.Binaries.FixtureFault) {
				t.Fatalf("fixture fault control included = %v", included)
			}
			fixtures := gatewaytest.StartFixtureSet(t, tc.binary, "FIXTURE_FAULT=drop-after-write")
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, gatewaytest.FixturePolicy(fixtures), gatewaytest.SeedOptions{})
			e.Start(gatewaytest.Binaries.Plain)
			before := fixtures["orders"].State()
			code, body := e.Request(http.MethodPost, "/orders", "application/json", `{"customer":"cust-001","item":"ITM-001","quantity":1}`, gatewaytest.Bearer(t, "cust-001")...)
			if code != tc.status {
				t.Fatalf("write: %d %s, want %d", code, body, tc.status)
			}
			receipts := fixtures["orders"].Receipts()
			if len(receipts) != 1 || receipts[0].Status != http.StatusCreated || receipts[0].Effect == "" || before.SHA256 == fixtures["orders"].State().SHA256 {
				t.Fatalf("expected exactly one real mutation: %+v", receipts)
			}
			if len(fixtures["inventory"].Receipts()) != 0 || len(fixtures["reports"].Receipts()) != 0 {
				t.Fatal("write reached another fixture")
			}
			if tc.status == http.StatusBadGateway {
				events := e.RequestEvents(receipts[0].RequestID, 2)
				outcome := gatewaytest.FindEvent(events, "request.forwarded", receipts[0].RequestID)
				if outcome == nil || outcome["decision"] != "upstream_failure" || outcome["reason"] != "outcome_unknown" {
					t.Fatalf("lost acknowledgement was not reported honestly: %v", events)
				}
			}
			t.Logf("client status %d; exactly one orders receipt, status 201, effect %s; independent state changed; other fixtures untouched", code, receipts[0].Effect)
		})
	}
}
