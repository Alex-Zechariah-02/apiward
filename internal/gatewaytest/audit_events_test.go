// Audit-stage comparisons reject invalid evidence and preserve JSON value equality.

package gatewaytest

import (
	"math"
	"testing"
)

func TestSameStagesRejectsUnencodableValues(t *testing.T) {
	t.Parallel()
	valid := map[string]any{"step": "pass"}
	invalid := map[string]any{"step": math.Inf(1)}
	for _, scenario := range []struct {
		name  string
		got   any
		want  map[string]any
		equal bool
	}{
		{"matching", valid, valid, true},
		{"different", valid, map[string]any{"step": "refused"}, false},
		{"wire numbers", map[string]any{"step": 1}, map[string]any{"step": float64(1)}, true},
		{"invalid actual", math.NaN(), valid, false},
		{"invalid expectation", valid, invalid, false},
		{"both invalid", math.NaN(), invalid, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if got := SameStages(scenario.got, scenario.want); got != scenario.equal {
				t.Fatalf("comparison returned %t, want %t", got, scenario.equal)
			}
		})
	}
}
