// Fixture process helpers and reproducible reset and replay.

package integration

import (
	"net/http"
	"slices"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	fixture "github.com/Alex-Zechariah-02/apiward/internal/services/testfixture"
)

func resetFixture(f *gatewaytest.FixtureProcess) fixture.State {
	f.T.Helper()
	return f.DecodeState(f.Call(http.MethodPost, "/reset", f.Secret))
}

// newFixtureEnv starts the three fixtures and a gateway serving gatewaytest.FixturePolicy.
func newFixtureEnv(t *testing.T) (*gatewaytest.Env, map[string]*gatewaytest.FixtureProcess) {
	t.Helper()
	fixtures := gatewaytest.StartFixtures(t)
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, gatewaytest.FixturePolicy(fixtures), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	if code, body, _ := e.HarnessCall("PUT", "/admin/blocked-accounts/former-01", `{"reason":"disabled test account"}`, "Idempotency-Key", "fixture-disabled-account"); code != http.StatusOK {
		t.Fatalf("seed containment: %d %s", code, body)
	}
	return e, fixtures
}

// Reset restores the seed exactly, and replaying the
// catalogue from it reproduces the same outcomes and final state.
func TestResetAndReplayAreReproducible(t *testing.T) {
	e, fixtures := newFixtureEnv(t)
	c := gatewaytest.LoadCatalogue(t)
	seedHash := map[string]string{}
	for _, f := range c.Fixtures {
		seedHash[f.Service] = f.SeedSHA256
	}

	type run struct {
		results []gatewaytest.StepResult
		final   map[string]string
	}
	var runs []run
	for range 2 {
		for name, f := range fixtures {
			s := resetFixture(f)
			if s.SHA256 != seedHash[name] || len(f.Receipts()) != 0 {
				t.Fatalf("reset of %s: state %s with %d receipts, want seed %s and none", name, s.SHA256, len(f.Receipts()), seedHash[name])
			}
		}
		r := run{results: gatewaytest.RunScenarios(t, e, fixtures, c), final: map[string]string{}}
		for name, f := range fixtures {
			r.final[name] = f.State().SHA256
		}
		runs = append(runs, r)
	}

	if !slices.Equal(runs[0].results, runs[1].results) {
		t.Fatalf("replays differ:\n%v\n%v", runs[0].results, runs[1].results)
	}
	for name := range fixtures {
		if runs[0].final[name] != runs[1].final[name] {
			t.Errorf("fixture %s final state differs between replays", name)
		}
	}
	// The catalogue changes orders and inventory, and never reports.
	if runs[0].final["orders"] == seedHash["orders"] || runs[0].final["inventory"] == seedHash["inventory"] || runs[0].final["reports"] != seedHash["reports"] {
		t.Fatalf("final states %v against seeds %v", runs[0].final, seedHash)
	}
	t.Logf("final states after each replay: %v", runs[0].final)
}
