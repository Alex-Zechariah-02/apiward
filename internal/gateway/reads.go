// Published state the request pipeline, the metrics listener and the Admin API
// read from the controller.

package gateway

import (
	"context"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Current returns the published generation, or nil when nothing may be served.
func (c *Controller) Current() *compile.Generation { return c.current.Load() }

// Verifier returns the published token verifier.
func (c *Controller) Verifier() *pipeline.Verifier { return c.verifier.Load() }

// Blocked returns the published blocked accounts.
func (c *Controller) Blocked() *store.BlockedAccounts { return c.blocked.Load() }

// Addresses returns the published blocked address list.
func (c *Controller) Addresses() *store.BlockedAddresses { return c.addresses.Load() }

// gauges reads the published policy revision, active temporary rules and
// blocked accounts for the metrics listener.
func (c *Controller) gauges() (revision int64, overrides, blocked int) {
	if generation := c.Current(); generation != nil {
		revision, overrides = generation.Revision, len(generation.Overrides)
	}
	if accounts := c.blocked.Load(); accounts != nil {
		blocked = len(*accounts)
	}
	return revision, overrides, blocked
}

// Capture reads the generation in force and the stored authority together,
// under the lock, without settling a deadline or publishing anything. The
// generation is nil when none is in force or it expired; the authority is
// then not read.
func (c *Controller) Capture(ctx context.Context) (*compile.Generation, store.Authority, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current := c.Current()
	if current == nil || current.Expired(compile.TrustedNow()) {
		return nil, store.Authority{}, nil
	}
	authority, err := c.store.Load(ctx)
	return current, authority, err
}
