// Transactional clock high-water reset and timed-authority teardown.

package store

import (
	"context"
	"fmt"
	"time"
)

// ResetClock ends any active provisional activation (disposition timed_out) and
// every active override (status expired), then sets deployment.high_water to
// now, all in one transaction. It returns the transition IDs of the ended
// timed authorities.
func (s *DB) ResetClock(ctx context.Context, baseID, actor string, a Authority, now time.Time) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var ended []string
	for _, o := range a.Overrides {
		ot := TransitionRecord{
			ID:       fmt.Sprintf("%s:override:%d", baseID, o.ID),
			Kind:     "tpo.expire",
			Actor:    actor,
			Target:   o.Target,
			Digest:   "operator",
			Override: o.ID,
		}
		if err := endOverride(ctx, tx, ot, o.ID, OverrideExpired, now); err != nil {
			return nil, err
		}
		ended = append(ended, ot.ID)
	}
	if a.Provisional != 0 {
		pt := TransitionRecord{
			ID:       baseID,
			Kind:     "operator.clock_reset",
			Actor:    actor,
			Target:   fmt.Sprintf("provisional revision %d", a.Provisional),
			Digest:   "operator",
			Revision: a.Confirmed,
		}
		if err := resolveProvisional(ctx, tx, pt, a, DispositionTimedOut, now); err != nil {
			return nil, err
		}
		ended = append(ended, pt.ID)
	} else {
		rt := TransitionRecord{
			ID:     baseID,
			Kind:   "operator.clock_reset",
			Actor:  actor,
			Target: "deployment.high_water",
			Digest: "operator",
		}
		if err := insertCommitted(ctx, tx, rt, now); err != nil {
			return nil, err
		}
	}
	// Reset high_water after insertCommitted, which applies MAX(high_water, now).
	if _, err := tx.ExecContext(ctx, `UPDATE deployment SET high_water = ? WHERE id = 1`, now.UnixMilli()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ended, nil
}
