// Catalogue scenarios through the gateway.

package integration

import (
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// Every catalogue operation runs
// through the real gateway and proxy on the intended fixture, with the
// expected business outcome and state change.
func TestCatalogueThroughGateway(t *testing.T) {
	e, fixtures := newFixtureEnv(t)
	c := gatewaytest.LoadCatalogue(t)

	instances := map[string]bool{}
	for _, f := range fixtures {
		instances[f.State().Instance] = true
	}
	if len(instances) != 3 {
		t.Fatalf("fixture instances %v, want three distinct processes", instances)
	}

	results := gatewaytest.RunScenarios(t, e, fixtures, c)
	if len(results) != len(c.Scenarios) {
		t.Fatalf("%d of %d steps ran", len(results), len(c.Scenarios))
	}
	ran := map[string]bool{}
	for _, r := range results {
		ran[r.Operation] = true
	}
	for _, op := range c.Operations {
		if !ran[op.ID] {
			t.Errorf("catalogue operation %s was never exercised", op.ID)
		}
	}
	e.AssertReceipts(0, 0, 0)
}
