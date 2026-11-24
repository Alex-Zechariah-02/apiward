// Settlement of the overrides and the provisional deadline due at one check:
// the due set is computed once, then one compile, one audit intent per
// ending, one store transaction, one publish and one outcome per ending.

package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/fault"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// due is the set of endings due together at one check.
type due struct {
	ended    []store.Override         // overrides whose expiry time has passed, in expiry order
	expiries []store.TransitionRecord // one per ended override, in the same order
	timeout  store.TransitionRecord   // the provisional base's timeout; ID empty if none
	next     []store.Override         // overrides still active after the endings
}

// settle ends, together, every override whose expiry time has passed at now
// and, when withProvisional is set, a provisional base whose deadline has
// passed. Mutation requests settle overrides only, so a request about a
// provisional base past its deadline is still answered as such. settle
// returns the stored authority once nothing more is due, and false when the
// endings could not be completed or the store could not be read; protected
// admission has then stopped.
func (c *Controller) settle(ctx context.Context, now time.Time, withProvisional bool) (store.Authority, bool) {
	a, err := c.store.Load(ctx)
	if err != nil {
		c.unavailable("store_unavailable", err.Error())
		return store.Authority{}, false
	}
	return c.endDue(ctx, a, now, withProvisional)
}

// dueAt computes the endings of a due at now.
func dueAt(a store.Authority, now time.Time, withProvisional bool) due {
	d := due{next: make([]store.Override, 0, len(a.Overrides))}
	for _, o := range a.Overrides {
		if now.Before(o.ExpiresAt) {
			d.next = append(d.next, o)
			continue
		}
		d.ended = append(d.ended, o)
	}
	slices.SortStableFunc(d.ended, func(x, y store.Override) int { return x.ExpiresAt.Compare(y.ExpiresAt) })
	for _, o := range d.ended {
		t := store.TransitionRecord{
			ID:       fmt.Sprintf("auto-expire:%d", o.ID),
			Kind:     "tpo.expire",
			Actor:    "controller",
			Target:   fmt.Sprintf("override %d", o.ID),
			Override: o.ID,
		}
		t.Digest = t.ID
		d.expiries = append(d.expiries, t)
	}
	if withProvisional && a.Provisional != 0 && !now.Before(a.Deadline) {
		d.timeout = store.TransitionRecord{
			ID:        fmt.Sprintf("auto-rollback:%d", a.Provisional),
			Kind:      "cpa.timeout",
			Actor:     "controller",
			Target:    fmt.Sprintf("revision %d", a.Provisional),
			Candidate: a.Candidate,
			Revision:  a.Confirmed,
		}
		d.timeout.Expected.Int64, d.timeout.Expected.Valid = a.Confirmed, true
		d.timeout.Digest = d.timeout.ID
	}
	return d
}

// records lists every ending's transition: the expiries, then the timeout.
func (d due) records() []store.TransitionRecord {
	if d.timeout.ID == "" {
		return d.expiries
	}
	return append(slices.Clone(d.expiries), d.timeout)
}

// endDue ends the endings of a due at now under their deterministic
// identities, so a repeated attempt can never apply twice. Every intent is
// recorded before the one store commit, the generation that follows is
// published once, and every outcome names it. Anything that cannot be
// completed stops protected admission rather than keep serving an override or
// provisional base that is being withdrawn.
func (c *Controller) endDue(ctx context.Context, a store.Authority, now time.Time, withProvisional bool) (store.Authority, bool) {
	d := dueAt(a, now, withProvisional)
	records := d.records()
	if len(records) == 0 {
		return a, true
	}
	ids := make([]string, 0, len(records))
	for _, t := range records {
		ids = append(ids, t.ID)
	}
	failed := func(reason string) (store.Authority, bool) {
		c.unavailable("transition_incomplete", fmt.Sprintf("%s not completed: %s", strings.Join(ids, ", "), reason))
		return store.Authority{}, false
	}
	stage := "tpo-expire"
	if d.timeout.ID != "" {
		stage = "timeout"
	}

	g, err := c.compileDue(ctx, a, d)
	if err != nil {
		c.logger.Error("compiling the policy that follows the due endings", "transitions", ids, "error", err)
		for _, t := range records {
			c.reject(ctx, t, "TARGET_INVALID", "", now)
		}
		return failed("effective policy invalid")
	}
	// Sequential: the audit queue reserves room for one acknowledged record
	// per request in flight, which a burst of concurrent intents could take.
	for _, t := range records {
		if err := c.commitAudit(ctx, audit.Event{Kind: "transition.intent", Transition: t.ID, Actor: t.Actor, Override: t.Override}); err != nil {
			c.unavailable("audit_reconcile_failed", fmt.Sprintf("%s not completed: audit unavailable", strings.Join(ids, ", ")))
			return store.Authority{}, false
		}
	}
	fault.CrashPoint(stage + "-before-commit")
	if err := c.store.CommitExpiries(ctx, a, d.expiries, d.timeout, now); err != nil {
		for _, id := range ids {
			if auditErr := c.commitAudit(ctx, audit.Event{Kind: "transition.failed", Transition: id, Reason: "STORE_ERROR"}); auditErr != nil {
				c.logger.Error("failure event not recorded", "transition", id, "error", auditErr)
			}
		}
		c.countFailure(ids[0], err)
		return failed("commit failed")
	}
	fault.CrashPoint(stage + "-after-commit")

	c.current.Store(g)
	c.state.Store(store.ModeNormal)
	c.scheduleDeadline(g)
	if d.timeout.ID != "" {
		c.warn(g)
	}
	fault.CrashPoint(stage + "-after-swap")
	for _, id := range ids {
		if err := c.store.MarkPublished(ctx, id, "publisher", now); err != nil {
			c.logger.Error("recording publication receipt", "error", err)
		}
	}
	fault.CrashPoint(stage + "-after-receipt")
	c.finishDue(ctx, a, d, g)
	if c.mode() != store.ModeNormal {
		return store.Authority{}, false
	}

	if d.timeout.ID == "" {
		a.Overrides = d.next
		return a, true
	}
	// The rollback changed the base and its activation record, which the
	// callers read from the stored authority.
	a, err = c.store.Load(ctx)
	if err != nil {
		c.unavailable("store_unavailable", err.Error())
		return store.Authority{}, false
	}
	return a, true
}

// compileDue compiles the generation that follows the endings of d: the
// rollback target when the provisional base times out, otherwise the active
// base of a, each with the overrides still active.
func (c *Controller) compileDue(ctx context.Context, a store.Authority, d due) (*compile.Generation, error) {
	if d.timeout.ID == "" {
		return authorityGeneration(c.network.Load(), a, d.next, c.config.Limits)
	}
	g, err := c.compileEffective(ctx, a.Confirmed, time.Time{}, d.next)
	if err == nil {
		err = fault.RollbackFault()
	}
	return g, err
}

// finishDue durably records each ending's outcome event, each naming the one
// generation g published for them all. A provisional base that stays pending
// is named in the override outcomes.
func (c *Controller) finishDue(ctx context.Context, a store.Authority, d due, g *compile.Generation) {
	for i, o := range d.ended {
		t := d.expiries[i]
		result := Outcome{Transition: t.ID, Outcome: "committed", Revision: g.Revision, Generation: g.ID,
			Override: o.ID, Target: o.Target, Expires: o.ExpiresAt, Disposition: store.OverrideExpired}
		event := audit.Event{Kind: outcomeKind(t), Transition: t.ID, Actor: t.Actor, Revision: g.Revision, Generation: g.ID,
			Override: o.ID, Target: o.Target, Expires: o.ExpiresAt}
		if a.Provisional != 0 && d.timeout.ID == "" {
			event.Provisional, event.RollbackTarget, event.Deadline = a.Provisional, a.Confirmed, a.Deadline.UTC()
		}
		c.finish(ctx, result, event)
	}
	if d.timeout.ID == "" {
		return
	}
	t := d.timeout
	result := Outcome{Transition: t.ID, Outcome: "committed", Revision: a.Confirmed, Generation: g.ID, Candidate: a.Candidate,
		Provisional: a.Provisional, RollbackTarget: a.Confirmed, Disposition: store.DispositionTimedOut}
	event := audit.Event{Kind: outcomeKind(t), Transition: t.ID, Actor: t.Actor, Revision: a.Confirmed, Generation: g.ID,
		Candidate: a.Candidate, Provisional: a.Provisional, RollbackTarget: a.Confirmed, Deadline: a.Deadline.UTC()}
	c.finish(ctx, result, event)
}
