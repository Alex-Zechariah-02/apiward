// Deadline timers, expiry checks and the end of a provisional base.

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/fault"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// scheduleDeadline arms the timer that wakes the controller at the earliest
// deadline the generation depends on. The timer only wakes the controller:
// every deadline is persisted and is also enforced on every request by the
// generation itself.
func (c *Controller) scheduleDeadline(g *compile.Generation) {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if g.NotAfter.IsZero() || fault.TimerFault() {
		return
	}
	c.timer = time.AfterFunc(g.NotAfter.Sub(compile.TrustedNow()), func() { c.expire(g) })
}

// Expired is called by the request path when the generation it
// captured has expired. It starts at most one check at a time, so a late or
// missing timer cannot keep the gateway refusing every request.
func (c *Controller) Expired(g *compile.Generation) {
	if !c.expiring.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.expiring.Store(false)
		c.expire(g)
	}()
}

// expire ends whatever made the published generation g expire. Under the
// controller lock it rechecks that g is still the published generation, so a
// timer or wake-up that arrives after another transition does nothing. A timer
// that fires before g has expired (the wall clock was set back after it was
// armed) is armed again.
func (c *Controller) expire(g *compile.Generation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := compile.TrustedNow()
	// After BeginStop no generation is published, so this is never g.
	if c.current.Load() != g {
		return
	}
	if !g.Expired(now) {
		c.scheduleDeadline(g)
		return
	}
	if _, settled := c.settle(context.Background(), now, true); !settled {
		return
	}
	// The generation expired, so a stored deadline must have passed and been
	// ended above. If none had, runtime and stored state disagree.
	if c.current.Load() == g {
		c.unavailable("deadline_mismatch", fmt.Sprintf("generation %s expired but no stored deadline has passed", g.ID))
	}
}

// prepare settles, in normal mode, the overrides due at now and returns
// the stored authority that follows; settled is false when an ending could
// not be completed or read, and err a failed read outside normal mode.
func (c *Controller) prepare(ctx context.Context, now time.Time) (a store.Authority, settled bool, err error) {
	if c.mode() == store.ModeNormal {
		a, settled = c.settle(ctx, now, false)
		return a, settled, nil
	}
	a, err = c.store.Load(ctx)
	return a, true, err
}

// endProvisional records the final disposition of the provisional base in a
// and publishes the base that follows it, through the same steps as any
// publication: compile the target before anything is committed, record the
// audit intent, commit, swap, record the receipt and the durable outcome.
// Confirmation republishes the provisional revision without its deadline.
// Every other disposition restores the rollback target; if that cannot be
// completed, the controller stops admitting protected requests rather than
// keep serving a provisional policy that is being withdrawn.
func (c *Controller) endProvisional(ctx context.Context, t store.TransitionRecord, a store.Authority, disposition string, now time.Time) (Outcome, int) {
	target := a.Confirmed
	if disposition == store.DispositionConfirmed {
		target = a.Provisional
	}
	stage := strings.TrimPrefix(t.Kind, "cpa.")
	failed := func(reason string, result Outcome, status int) (Outcome, int) {
		if disposition != store.DispositionConfirmed {
			c.unavailable("transition_incomplete", fmt.Sprintf("%s (%s of revision %d) not completed: %s", t.ID, stage, a.Provisional, reason))
		}
		return result, status
	}

	// The base that follows is compiled with the overrides active now, never
	// with an earlier effective policy: an override that ended while the
	// base was provisional stays ended.
	g, err := c.compileEffective(ctx, target, time.Time{}, a.Overrides)
	if err == nil && disposition != store.DispositionConfirmed {
		err = fault.RollbackFault()
	}
	if err != nil {
		c.logger.Error("compiling the base after the provisional revision", "revision", target, "error", err)
		result, status := c.reject(ctx, t, "TARGET_INVALID", "", now)
		return failed("target revision invalid", result, status)
	}

	if err := c.commitAudit(ctx, audit.Event{Kind: "transition.intent", Transition: t.ID, Actor: t.Actor}); err != nil {
		result, status := auditUnavailable(t.ID)
		return failed("audit unavailable", result, status)
	}
	fault.CrashPoint(stage + "-before-commit")
	t.Revision = target
	if err := c.store.CommitResolution(ctx, t, a, disposition, now); err != nil {
		result, status := c.commitFailure(ctx, t.ID, err)
		return failed("commit failed", result, status)
	}
	fault.CrashPoint(stage + "-after-commit")

	c.publishGeneration(g)
	c.state.Store(store.ModeNormal)
	c.scheduleDeadline(g)
	c.warn(g)
	fault.CrashPoint(stage + "-after-swap")
	if err := c.store.MarkPublished(ctx, t.ID, "publisher", now); err != nil {
		c.logger.Error("recording publication receipt", "error", err)
	}
	fault.CrashPoint(stage + "-after-receipt")

	result := Outcome{
		Transition:     t.ID,
		Outcome:        "committed",
		Revision:       target,
		Generation:     g.ID,
		Candidate:      a.Candidate,
		Provisional:    a.Provisional,
		RollbackTarget: a.Confirmed,
		Disposition:    disposition,
	}
	event := audit.Event{
		Kind:           outcomeKind(t),
		Transition:     t.ID,
		Actor:          t.Actor,
		Revision:       target,
		Generation:     g.ID,
		Candidate:      a.Candidate,
		Provisional:    a.Provisional,
		RollbackTarget: a.Confirmed,
		Deadline:       a.Deadline.UTC(),
	}
	return c.finish(ctx, result, event)
}
