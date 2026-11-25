// Operator clock-recovery command.

package operator

import (
	"fmt"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// runRecoverClock resets deployment.high_water to now when it sits more than
// store.ClockTolerance ahead of the wall clock, ending any active provisional
// activation and overrides in the same transaction so no deadline is extended.
func runRecoverClock(o *operatorContext) (int, error) {
	st, err := store.OpenStore(o.config.Database)
	if err != nil {
		return 1, err
	}
	defer st.Close()
	a, err := st.Load(o.ctx)
	if err != nil {
		return 1, err
	}
	now := time.Now()
	if !now.Before(a.HighWater.Add(-store.ClockTolerance)) {
		fmt.Println("no change")
		return 0, nil
	}
	o.openAudit()

	baseID := fmt.Sprintf("operator-clock-reset:%d", now.UnixMilli())
	if err := o.record(audit.Event{Kind: "transition.intent", Transition: baseID, Target: "deployment.high_water"}); err != nil {
		return 1, err
	}
	ended, err := st.ResetClock(o.ctx, baseID, o.actor, a, now)
	if err != nil {
		return 1, fmt.Errorf("resetting clock high-water mark: %w", err)
	}
	if err := o.record(audit.Event{
		Kind:         "operator.clock_reset",
		Transition:   baseID,
		Target:       "deployment.high_water",
		OldHighWater: a.HighWater.UTC(),
		NewHighWater: now.UTC(),
		Ended:        ended,
	}); err != nil {
		return 1, err
	}
	auditedAt := time.Now()
	if err := st.MarkAudited(o.ctx, baseID, auditedAt); err != nil {
		return 1, err
	}
	for _, id := range ended {
		if id == baseID {
			continue
		}
		if err := st.MarkAudited(o.ctx, id, auditedAt); err != nil {
			return 1, err
		}
	}
	fmt.Printf("reset clock high_water from %s to %s (ended %d timed transitions)\n",
		a.HighWater.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), len(ended))
	return 0, nil
}
