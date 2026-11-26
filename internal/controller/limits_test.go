// The override limits at their bounds: the largest rate count, a full set
// of active overrides, and the request past it.

package controller

import (
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

// A rate override may name the largest count a policy rate rule accepts.
func TestOverrideCountAtBound(t *testing.T) {
	o, err := rateOverride(store.OverrideException, "read-a", compile.MaxRateCount, 60).check()
	if err != nil || o.Count != compile.MaxRateCount {
		t.Fatalf("count %d: %+v %v", compile.MaxRateCount, o, err)
	}
}

// Exactly MaxActiveOverrides overrides are not too many for a generation,
// while a proposal is refused once that many are active.
func TestOverrideSetAtBound(t *testing.T) {
	full := make([]store.Override, store.MaxActiveOverrides)
	if _, err := effectiveGeneration(closedNetwork(t), storetest.Protected(), 7, time.Time{}, full, policy.Limits{}); overrideErrorCode(err) == "LIMIT_EXCEEDED@overrides" {
		t.Fatalf("%d overrides refused as too many", len(full))
	}
	a := store.Authority{Mode: store.ModeNormal, Confirmed: 1, Overrides: full}
	request := permitOverride(store.OverrideException, "READER", "write-a", 60)
	if _, code, _, _ := proposeOverride(a, 1, request, "admin", time.Now()); code != "OVERRIDE_LIMIT" {
		t.Fatalf("with %d active: %q, want OVERRIDE_LIMIT", len(full), code)
	}
	a.Overrides = full[:len(full)-1]
	if _, code, _, _ := proposeOverride(a, 1, request, "admin", time.Now()); code == "OVERRIDE_LIMIT" {
		t.Fatalf("with %d active: refused at the bound", len(a.Overrides))
	}
}
