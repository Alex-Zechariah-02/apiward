// Admin API advice and alerts end to end.

package integration

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/policy"
)

// The advice and alerts reads answer through the Admin API.
func TestAdminAdviceAndAlerts(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	p := e.ProtectedPolicy()
	p.APIs[0].ResponseHeaders = &policy.ResponseHeaders{HSTS: true}
	gatewaytest.Seed(t, e.Database, p, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	code, body, _ := e.As(admin, "GET", "/admin/advice", "")
	var advice struct {
		Rules    string            `json:"rules"`
		Warnings []monitor.Finding `json:"warnings"`
		Unused   struct {
			Withheld *string `json:"withheld"`
		} `json:"unused_permits"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &advice) != nil || advice.Rules != monitor.AdviceRules || advice.Unused.Withheld == nil {
		t.Fatalf("advice: %d %s", code, body)
	}
	// The harness policy has signed-in endpoints without rate limits, and the
	// standalone gateway serves plain HTTP, so HSTS is never sent.
	for _, id := range []string{"W4", "W5"} {
		if !slices.ContainsFunc(advice.Warnings, func(f monitor.Finding) bool { return f.ID == id }) {
			t.Errorf("warnings without %s: %s", id, body)
		}
	}
	if code, body, _ := e.As(admin, "GET", "/admin/advice?candidate=999", ""); code != 404 {
		t.Errorf("unknown draft: %d %s", code, body)
	}
	if code, body, _ := e.As(admin, "GET", "/admin/advice?candidate=x", ""); code != 400 {
		t.Errorf("bad draft id: %d %s", code, body)
	}
	for range 25 {
		e.Get("/a/x")
	}
	code, body, _ = e.As(admin, "GET", "/admin/alerts", "")
	var alerts struct {
		Alerts []monitor.Finding `json:"alerts"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &alerts) != nil || !slices.ContainsFunc(alerts.Alerts, func(f monitor.Finding) bool { return f.ID == "A1" }) {
		t.Errorf("25 refusals with nothing before raise a spike: %d %s", code, body)
	}
}
