// The fixture policy and its operation catalogue, and the tokens and roles
// scenarios use.

package gatewaytest

import (
	"slices"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	fixture "github.com/Alex-Zechariah-02/apiward/internal/services/testfixture"
)

// Body schemas of the fixture writes. They state the request shape the
// fixtures accept; business rules such as known items, ownership and the
// quantity range stay with the fixtures.
const (
	OrdersCreateSchema = `{"type":"object","additionalProperties":false,"required":["customer","item","quantity"],"properties":{` +
		`"customer":{"type":"string","minLength":1,"maxLength":64},` +
		`"item":{"type":"string","minLength":1,"maxLength":64},` +
		`"quantity":{"type":"integer"}}}`
	InventoryAdjustSchema = `{"type":"object","additionalProperties":false,"required":["delta"],"properties":{` +
		`"delta":{"type":"integer","minimum":-100,"maximum":100}}}`
)

// fixtureRate is the rate rule on every authenticated fixture operation. It
// is wide enough that no catalogue replay reaches it; rate tests use their
// own, tighter rules.
func fixtureRate() *policy.RateRule {
	return &policy.RateRule{Algorithm: "sliding-window", Count: 100, WindowSeconds: 60, Key: "subject"}
}

// FixturePolicy is the gateway policy for the three fixtures. It is written
// here by hand from the fixture contract, not generated from the catalogue,
// so a comparison between the two is meaningful.
func FixturePolicy(fixtures map[string]*FixtureProcess) policy.Policy {
	return policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams: []policy.Upstream{
			{ID: "orders-svc", Dial: fixtures["orders"].Addr},
			{ID: "inventory-svc", Dial: fixtures["inventory"].Addr},
			{ID: "reports-svc", Dial: fixtures["reports"].Addr},
		},
		APIs: []policy.API{
			{ID: "orders", Upstream: "orders-svc"},
			{ID: "inventory", Upstream: "inventory-svc"},
			{ID: "reports", Upstream: "reports-svc"},
		},
		Operations: []policy.Operation{
			{ID: "orders.list", API: "orders", Method: "GET", Target: "/orders", Access: "allow", Auth: "required", Rate: fixtureRate()},
			{ID: "orders.get", API: "orders", Method: "GET", Target: "/orders/*", Access: "allow", Auth: "required", Rate: fixtureRate()},
			{ID: "orders.create", API: "orders", Method: "POST", Target: "/orders", Access: "allow", Auth: "required",
				Body: JSONBody(1024, OrdersCreateSchema), Rate: fixtureRate()},
			{ID: "inventory.health", API: "inventory", Method: "GET", Target: "/inventory/health", Access: "allow", Auth: "none"},
			{ID: "inventory.get", API: "inventory", Method: "GET", Target: "/inventory/items/*", Access: "allow", Auth: "required", Rate: fixtureRate()},
			{ID: "inventory.adjust", API: "inventory", Method: "PATCH", Target: "/inventory/items/*", Access: "allow", Auth: "required",
				Body: JSONBody(1024, InventoryAdjustSchema), Rate: fixtureRate()},
			{ID: "reports.sales", API: "reports", Method: "GET", Target: "/reports/sales", Access: "allow", Auth: "required", Rate: fixtureRate()},
			{ID: "reports.summary", API: "reports", Method: "GET", Target: "/reports/summary", Access: "allow", Auth: "required", Rate: fixtureRate()},
		},
		Roles: []policy.Role{{ID: "CUSTOMER"}, {ID: "STAFF"}, {ID: "MANAGER"}},
		Permits: []policy.Permit{
			{Role: "STAFF", Operation: "orders.list"},
			{Role: "MANAGER", Operation: "orders.list"},
			{Role: "CUSTOMER", Operation: "orders.get"},
			{Role: "STAFF", Operation: "orders.get"},
			{Role: "CUSTOMER", Operation: "orders.create"},
			{Role: "STAFF", Operation: "inventory.get"},
			{Role: "MANAGER", Operation: "inventory.get"},
			{Role: "STAFF", Operation: "inventory.adjust"},
			{Role: "MANAGER", Operation: "reports.sales"},
			{Role: "STAFF", Operation: "reports.summary"},
			{Role: "MANAGER", Operation: "reports.summary"},
		},
	}
}

// Bearer is the Authorization header pair carrying a valid token for subject.
func Bearer(t *testing.T, subject string) []string {
	t.Helper()
	return []string{"Authorization", "Bearer " + Issuer.TokenFor(t, subject)}
}

// CatalogueRoles gives each catalogue subject's roles in the form the gateway
// forwards them: sorted and comma-separated.
func CatalogueRoles(c fixture.Catalogue) map[string]string {
	roles := map[string]string{}
	for _, s := range c.Subjects {
		roles[s.ID] = strings.Join(slices.Sorted(slices.Values(s.Roles)), ",")
	}
	return roles
}

// LoadCatalogue reads the fixture operation catalogue.
func LoadCatalogue(t *testing.T) fixture.Catalogue {
	t.Helper()
	c, err := fixture.LoadCatalogue()
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	return c
}
