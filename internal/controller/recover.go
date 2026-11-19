// Recovery from a transient control-plane failure: while protected admission
// is unavailable for a reason a later attempt can clear (the database or the
// audit log failed for a moment, the clock stepped back), the controller
// reads its authority again with a growing pause, and publishes it once the
// read succeeds. Until then every protected request stays refused.

package controller

import (
	"context"
	"slices"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// The pause before the first retry, and the longest pause: a failure that
// lasts is retried once a minute, which costs one authority read.
const (
	firstRetry = time.Second
	lastRetry  = time.Minute
)

// retryable are the unavailable states a later read can clear. The others
// (an invalid stored policy, a rollback target or deadline that does not
// match, an incomplete transition) need an administrator or an operator.
var retryable = []string{"store_unavailable", "audit_reconcile_failed", "clock_regression"}

// scheduleRetry arms one retry for state, with mu held. A stop, a database
// that never opened, or a state no retry clears schedules nothing.
func (c *Controller) scheduleRetry(state string) {
	if c.stopping || c.store == nil || !slices.Contains(retryable, state) || c.retry != nil {
		return
	}
	c.retryWait = min(max(2*c.retryWait, firstRetry), lastRetry)
	c.retry = time.AfterFunc(c.retryWait, c.retryAuthority)
}

// retryAuthority reads the blocked lists and the authority again. A success
// publishes a generation and resets the pause; a failure calls unavailable,
// which schedules the next retry.
func (c *Controller) retryAuthority() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retry = nil
	if c.stopping || !slices.Contains(retryable, c.mode()) {
		return
	}
	c.logger.Info("retrying the stored authority", "after", c.mode())
	ctx := context.Background()
	blocked, err := c.store.BlockedAccounts(ctx)
	if err != nil {
		c.unavailable("store_unavailable", "reading blocked accounts: "+err.Error())
		return
	}
	addresses, err := c.store.BlockedAddresses(ctx)
	if err != nil {
		c.unavailable("store_unavailable", "reading blocked addresses: "+err.Error())
		return
	}
	c.blocked.Store(&blocked)
	c.publishAddresses(addresses)
	c.reconcile(compile.TrustedNow())
	if !slices.Contains(retryable, c.mode()) {
		c.retryWait = 0
	}
}

// stopRetry cancels a pending retry, with mu held.
func (c *Controller) stopRetry() {
	if c.retry != nil {
		c.retry.Stop()
		c.retry = nil
	}
}
