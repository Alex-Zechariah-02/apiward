// Ingress refusals are counted in the security log's ingress summary, not
// recorded one by one.

package gateway

import (
	"maps"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// eventReason is the one record of a request and its reason.
func eventReason(e *gatewaytest.Env, requestID string) (map[string]any, string) {
	e.T.Helper()
	ev := eventOf(e, requestID, 1)
	reason, _ := ev["reason"].(string)
	return ev, reason
}

// checkIngressSummary stops c, so its audit log writes the ingress refusals
// it counted, then checks their counts by reason and that none of the
// requests ids has a record of its own.
func checkIngressSummary(t *testing.T, e *gatewaytest.Env, c *controller.Controller, want map[string]int, ids []string) {
	t.Helper()
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	events := e.AuditEvents()
	if got := gatewaytest.SummaryCounts(events); !maps.Equal(got, want) {
		t.Fatalf("ingress summary %v, want %v", got, want)
	}
	if ev := gatewaytest.RecordOf(events, ids); ev != nil {
		t.Fatalf("ingress refusal recorded on its own: %v", ev)
	}
}
