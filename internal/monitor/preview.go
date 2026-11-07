// How a recent request would be decided under another generation, for
// impact previews.

package monitor

import (
	"net/http"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// PreviewDecision shares canonical matching and permit evaluation with the
// request pipeline. It deliberately does not touch counters or validate bodies.
func PreviewDecision(g *compile.Generation, event Observed) (decision, code, operation string, known bool) {
	if event.routingPath == "" {
		return "refused", "bad_request", "", true
	}
	// A preflight's event does not keep the method it asked about.
	if event.Code != nil && (*event.Code == "cors_preflight" || *event.Code == "cors_refused") {
		return "", "", "", false
	}
	// Events keep neither host nor headers, so conditions cannot be replayed.
	if g.Conditioned(event.routingPath, event.Method) {
		return "", "", "", false
	}
	target, rule := g.Match(event.routingPath, event.Method, compile.Inbound{})
	if target == nil {
		return "refused", "not_found", "", true
	}
	if rule == nil {
		return "refused", "method_not_allowed", "", true
	}
	if !rule.AddressAllowed(event.ClientAddress) {
		return "refused", "address_not_allowed", rule.Operation(), true
	}
	if !rule.Permitted() {
		return "refused", "forbidden", rule.Operation(), true
	}
	if !rule.Public() {
		if !event.identityKnown {
			return "", "", rule.Operation(), false
		}
		if event.Subject == nil {
			return "refused", "unauthenticated", rule.Operation(), true
		}
		if event.Stage == "blocked" {
			return "refused", "account_blocked", rule.Operation(), true
		}
		if _, _, reason := g.Authorise(event.assertedRoles, rule); reason != "" {
			return "refused", "forbidden", rule.Operation(), true
		}
	}
	return "allowed", "", rule.Operation(), true
}

// traffic failures are refusals from the caller's perspective, while request
// events retain the distinction between refusal and an unknown upstream result.
func WasAllowed(event RequestView) bool {
	return event.Decision == "allowed" && event.Status >= http.StatusOK
}
