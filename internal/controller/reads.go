// Published state the request pipeline, the metrics listener and the Admin API
// read from the controller.

package controller

import (
	"context"
	"slices"
	"time"

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

// AddressIndex returns the lookup of the blocked address list; nil until
// the list was read from the store.
func (c *Controller) AddressIndex() *store.AddressIndex { return c.addressIndex.Load() }

// publishAddresses publishes a blocked address list and its lookup; the
// index first, so a request that sees the list finds its index too.
func (c *Controller) publishAddresses(list store.BlockedAddresses) {
	c.addressIndex.Store(store.NewAddressIndex(list))
	c.addresses.Store(&list)
}

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
	var addresses int64
	if list := c.addresses.Load(); list != nil {
		addresses = int64(len(*list))
	}
	used, budget := c.audit.Budget()
	gauges := []monitor.Gauge{
		{Name: "gateway_policy_revision", Value: revision},
		{Name: "gateway_temporary_rules_active", Value: overrides},
		{Name: "gateway_blocked_accounts", Value: blocked},
		{Name: "gateway_blocked_addresses", Value: addresses},
		{Name: "gateway_audit_bytes", Value: used},
		{Name: "gateway_audit_budget_bytes", Value: budget},
		{Name: "gateway_audit_records_lost_total", Value: int64(c.audit.Losses()), Counter: true}, // #nosec G115 -- a count of records, far below 2^63
		{Name: "gateway_audit_evictions_total", Value: int64(c.audit.Evictions()), Counter: true}, // #nosec G115 -- a count of files, far below 2^63
		{Name: "gateway_control_store_failures_total", Value: c.failures.Load(), Counter: true},
	}
	gauges = append(gauges, auditGauges(c.audit)...)
	var lastCheckpoint int64
	if cp := c.audit.Checkpoint(); cp != nil {
		lastCheckpoint = cp.Time.Unix()
	}
	gauges = append(gauges,
		monitor.Gauge{Name: "gateway_audit_chain_batches_total", Value: int64(c.audit.ChainBatches()), Counter: true}, // #nosec G115 -- a count of batches, far below 2^63
		monitor.Gauge{Name: "gateway_audit_last_checkpoint_timestamp_seconds", Value: lastCheckpoint},
	)
	if c.config.DataCertificateExpiry != nil {
		if exp, ok := c.config.DataCertificateExpiry(); ok {
			gauges = append(gauges, monitor.Gauge{
				Name:   "gateway_tls_certificate_not_after_seconds",
				Value:  exp.Unix(),
				Labels: []string{"role", "data", "profile", ""},
			})
		}
	}
	if net := c.Network(); net != nil {
		for _, p := range net.Profiles() {
			if p.ClientCertificate && p.ExpiresAt != nil {
				gauges = append(gauges, monitor.Gauge{
					Name:   "gateway_tls_certificate_not_after_seconds",
					Value:  p.ExpiresAt.Unix(),
					Labels: []string{"role", "upstream", "profile", p.ID},
				})
			}
		}
	}
	return gauges
}

// Capture reads the generation in force and the stored authority together,
// without settling a deadline or publishing anything. The generation is nil
// when none is in force or it expired; the authority is then not read.
//
// A read-only preview must not wait behind a mutation or hold one up, so
// the pair is first read without the lock and kept only when the
// generation is still the one in force and was compiled from that
// authority's base and overrides; a mutation that commits between the reads
// fails the check, and the pair is then read under the lock.
func (c *Controller) Capture(ctx context.Context) (*compile.Generation, store.Authority, error) {
	current := c.Current()
	if current == nil || current.Lapsed() {
		return nil, store.Authority{}, nil
	}
	authority, err := c.store.Load(ctx)
	if err == nil && c.Current() == current && compiledFrom(current, authority) {
		return current, authority, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	current = c.Current()
	if current == nil || current.Lapsed() {
		return nil, store.Authority{}, nil
	}
	authority, err = c.store.Load(ctx)
	return current, authority, err
}

// compiledFrom reports whether g is the generation of a's active base with
// a's active overrides and deadlines (see effectiveGeneration).
func compiledFrom(g *compile.Generation, a store.Authority) bool {
	var notAfter time.Time
	if a.Provisional != 0 {
		notAfter = a.Deadline
	}
	for _, o := range a.Overrides {
		if notAfter.IsZero() || o.ExpiresAt.Before(notAfter) {
			notAfter = o.ExpiresAt
		}
	}
	return a.Mode == store.ModeNormal && g.Revision == a.Revision && g.NotAfter.Equal(notAfter) &&
		slices.Equal(g.Overrides, overrideIDs(a.Overrides))
}
