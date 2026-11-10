// Published state the request pipeline, the metrics listener and the Admin API
// read from the controller.

package controller

import (
	"context"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Current returns the published generation, or nil when nothing may be served.
func (c *Controller) Current() *compile.Generation { return c.current.Load() }

// Verifier returns the published token verifier.
func (c *Controller) Verifier() *pipeline.Verifier { return c.verifier.Load() }

// Network returns the published upstream network settings.
func (c *Controller) Network() *forward.Network { return c.network.Load() }

// Blocked returns the published blocked accounts.
func (c *Controller) Blocked() *store.BlockedAccounts { return c.blocked.Load() }

// Addresses returns the published blocked address list.
func (c *Controller) Addresses() *store.BlockedAddresses { return c.addresses.Load() }

// Audit returns the audit log the controller opened; it stays open until
// the stop.
func (c *Controller) Audit() *audit.AuditLog { return c.audit }

// Observations returns the in-memory observations of requests and events.
func (c *Controller) Observations() *monitor.Observations { return c.observations }

// Sessions returns the administrator sessions, which the controller revokes
// when an administrator's credentials change.
func (c *Controller) Sessions() *session.Table { return c.sessions }

// Settings returns the configuration with its defaults applied.
func (c *Controller) Settings() Config { return c.config }

// Reads returns the store's read methods; nil while no database is open.
func (c *Controller) Reads() store.Reads {
	if c.store == nil {
		return nil
	}
	return c.store
}

// Gauges reads the published policy revision, active temporary rules,
// blocked accounts and the audit log's bytes and budget for the metrics
// listener.
func (c *Controller) Gauges() []monitor.Gauge {
	var revision, overrides, blocked int64
	if generation := c.Current(); generation != nil {
		revision, overrides = generation.Revision, int64(len(generation.Overrides))
	}
	if accounts := c.blocked.Load(); accounts != nil {
		blocked = int64(len(*accounts))
	}
	used, budget := c.audit.Budget()
	return []monitor.Gauge{
		{Name: "gateway_policy_revision", Value: revision},
		{Name: "gateway_temporary_rules_active", Value: overrides},
		{Name: "gateway_blocked_accounts", Value: blocked},
		{Name: "gateway_audit_bytes", Value: used},
		{Name: "gateway_audit_budget_bytes", Value: budget},
	}
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
