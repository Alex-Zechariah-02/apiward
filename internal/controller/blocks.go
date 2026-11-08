// Changes to trust and containment published without a policy change:
// blocked accounts, blocked addresses and reloaded keys, each with its
// receipt.

package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/fault"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func controlError(code string) json.RawMessage {
	body, _ := json.Marshal(map[string]string{"error": code})
	return body
}

// replayControl uses the existing actor-scoped transition identity and digest;
// its successful body is the original response, even after later mutations.
// The caller holds c.mu.
func (c *Controller) replayControl(ctx context.Context, t store.TransitionRecord) (json.RawMessage, int, bool) {
	if !c.ready() {
		return controlError("gateway_unavailable"), http.StatusServiceUnavailable, true
	}
	outcome, status, done := c.replay(ctx, t)
	if !done {
		return nil, 0, false
	}
	if status != http.StatusOK {
		return controlError(strings.ToLower(outcome.Reason)), status, true
	}
	body, err := c.store.ControlResult(ctx, t.ID)
	if err != nil {
		c.logger.Error("reading control receipt", "error", err)
		return controlError("gateway_unavailable"), http.StatusServiceUnavailable, true
	}
	return body, status, true
}

func (c *Controller) rejectControl(ctx context.Context, t store.TransitionRecord, reason string, now time.Time) (json.RawMessage, int) {
	outcome, status := c.reject(ctx, t, reason, "", now)
	return controlError(strings.ToLower(outcome.Reason)), status
}

// finishControl follows the same durable intent, commit, publication and audit
// sequence as policy mutations. A lost acknowledgement is retried by identity;
// it never re-applies a block or re-reads keys as a hidden retry.
func (c *Controller) finishControl(ctx context.Context, t store.TransitionRecord, result any, change func(*sql.Tx) error, publish func(), now time.Time) (json.RawMessage, int) {
	body, err := json.Marshal(result)
	if err != nil {
		return controlError("gateway_unavailable"), http.StatusServiceUnavailable
	}
	if err := c.commitAudit(ctx, audit.Event{Kind: "transition.intent", Transition: t.ID, Actor: t.Actor}); err != nil {
		return controlError("gateway_unavailable"), http.StatusServiceUnavailable
	}
	fault.CrashPoint("before-commit")
	if err := c.store.CommitControl(ctx, t, body, change, now); err != nil {
		c.logger.Error("committing control change", "error", err)
		return controlError("gateway_unavailable"), http.StatusServiceUnavailable
	}
	fault.CrashPoint("after-commit")
	publish()
	fault.CrashPoint("after-swap")
	if err := c.store.MarkPublished(ctx, t.ID, "publisher", now); err != nil {
		c.logger.Error("recording control publication receipt", "error", err)
	}
	fault.CrashPoint("after-receipt")
	outcome, status := c.finish(ctx, Outcome{Transition: t.ID, Outcome: "committed"}, audit.Event{Kind: t.Kind, Transition: t.ID, Actor: t.Actor, Target: t.Target})
	if status != http.StatusOK {
		// The change is committed and in force; only its outcome event is
		// missing, which "gateway_unavailable" would deny.
		return controlError(strings.ToLower(outcome.Reason)), status
	}
	return body, status
}

func (c *Controller) reloadKeys(ctx context.Context, t store.TransitionRecord) (json.RawMessage, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if body, status, done := c.replayControl(ctx, t); done {
		return body, status
	}
	now := compile.TrustedNow()
	if c.config.ReloadKeys == nil {
		return c.rejectControl(ctx, t, "KEYS_INVALID", now)
	}
	trust, network, err := c.config.ReloadKeys()
	if err != nil {
		return c.rejectControl(ctx, t, "KEYS_INVALID", now)
	}
	// The served generation's upstreams must stay reachable: a reload may
	// not remove a TLS profile it uses or the public addresses it needs.
	if g := c.current.Load(); g != nil && g.CheckNetwork(network) != nil {
		return c.rejectControl(ctx, t, "KEYS_INVALID", now)
	}
	current := c.verifier.Load()
	if trust.Issuer != current.Issuer() || trust.Audience != current.Audience() {
		return c.rejectControl(ctx, t, "KEYS_INVALID", now)
	}
	loaded, err := pipeline.LoadVerifier(trust)
	if err != nil {
		return c.rejectControl(ctx, t, "KEYS_INVALID", now)
	}
	return c.finishControl(ctx, t, struct {
		Items []pipeline.KeyInfo `json:"items"`
	}{loaded.Keys()}, nil, func() {
		loaded.AdoptUses(c.verifier.Load())
		c.verifier.Store(loaded)
		c.network.Store(network)
	}, now)
}

func (c *Controller) changeBlock(ctx context.Context, t store.TransitionRecord, reason string) (json.RawMessage, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if body, status, done := c.replayControl(ctx, t); done {
		return body, status
	}
	now := compile.TrustedNow().UTC().Truncate(time.Millisecond)
	current := c.blocked.Load()
	if current == nil {
		return controlError("gateway_unavailable"), http.StatusServiceUnavailable
	}
	previous, found := (*current)[t.Target]
	next := maps.Clone(*current)
	var result any
	var change func(*sql.Tx) error
	if t.Kind == "account.block" {
		entry := store.BlockedAccount{Subject: t.Target, Reason: reason, BlockedBy: t.Actor, BlockedAt: now}
		if found && previous.Reason == reason {
			entry = previous
		}
		next[t.Target] = entry
		result = entry
		change = func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO blocked_account (subject, reason, blocked_by, blocked_at) VALUES (?, ?, ?, ?)
				ON CONFLICT(subject) DO UPDATE SET reason=excluded.reason, blocked_by=excluded.blocked_by, blocked_at=excluded.blocked_at`,
				entry.Subject, entry.Reason, entry.BlockedBy, entry.BlockedAt.UnixMilli())
			return err
		}
	} else {
		if !found {
			return c.rejectControl(ctx, t, "NOT_FOUND", now)
		}
		delete(next, t.Target)
		result = map[string]any{"subject": t.Target, "unblocked": true}
		change = func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `DELETE FROM blocked_account WHERE subject = ?`, t.Target)
			return err
		}
	}
	return c.finishControl(ctx, t, result, change, func() { c.blocked.Store(&next) }, now)
}

// changeAddress blocks or unblocks one range. Expired entries are dropped
// from the list and the store by the same write; an expired entry is not
// found. Blocking again with the same reason and expiry keeps the entry.
func (c *Controller) changeAddress(ctx context.Context, t store.TransitionRecord, entry store.BlockedAddress) (json.RawMessage, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if body, status, done := c.replayControl(ctx, t); done {
		return body, status
	}
	now := compile.TrustedNow().UTC().Truncate(time.Millisecond)
	current := c.addresses.Load()
	if current == nil {
		return controlError("gateway_unavailable"), http.StatusServiceUnavailable
	}
	next := maps.Clone(*current)
	maps.DeleteFunc(next, func(_ string, e store.BlockedAddress) bool { return !e.Active(now) })
	previous, found := next[entry.Range]
	var result any
	var change func(*sql.Tx) error
	if t.Kind == "address.block" {
		if !found && len(next) >= store.MaxBlockedAddresses {
			return c.rejectControl(ctx, t, "LIMIT_EXCEEDED", now)
		}
		entry.BlockedBy, entry.BlockedAt = t.Actor, now
		if found && previous.Reason == entry.Reason && slices.Equal(expiry(previous), expiry(entry)) {
			entry = previous
		}
		next[entry.Range] = entry
		result = entry
		change = func(tx *sql.Tx) error { return store.SaveBlockedAddress(ctx, tx, entry, now) }
	} else {
		if !found {
			return c.rejectControl(ctx, t, "NOT_FOUND", now)
		}
		delete(next, entry.Range)
		result = map[string]any{"range": entry.Range, "unblocked": true}
		change = func(tx *sql.Tx) error { return store.DeleteBlockedAddress(ctx, tx, entry.Range, now) }
	}
	return c.finishControl(ctx, t, result, change, func() { c.addresses.Store(&next) }, now)
}

// expiry is an entry's expiry as a comparable list: empty when it has none.
func expiry(entry store.BlockedAddress) []time.Time {
	if entry.ExpiresAt == nil {
		return nil
	}
	return []time.Time{*entry.ExpiresAt}
}

// Block adds t's subject to the blocked accounts, or keeps an entry with the
// same reason, and records t's receipt. Each method here sets t's kind
// itself, so a caller cannot run one change under another's name.
func (c *Controller) Block(ctx context.Context, t store.TransitionRecord, reason string) (json.RawMessage, int) {
	t.Kind = "account.block"
	return c.changeBlock(ctx, t, reason)
}

// Unblock removes t's subject from the blocked accounts.
func (c *Controller) Unblock(ctx context.Context, t store.TransitionRecord) (json.RawMessage, int) {
	t.Kind = "account.unblock"
	return c.changeBlock(ctx, t, "")
}

// BlockAddress adds entry's range to the blocked address list.
func (c *Controller) BlockAddress(ctx context.Context, t store.TransitionRecord, entry store.BlockedAddress) (json.RawMessage, int) {
	t.Kind = "address.block"
	return c.changeAddress(ctx, t, entry)
}

// UnblockAddress removes entry's range from the blocked address list.
func (c *Controller) UnblockAddress(ctx context.Context, t store.TransitionRecord, entry store.BlockedAddress) (json.RawMessage, int) {
	t.Kind = "address.unblock"
	return c.changeAddress(ctx, t, entry)
}

// ReloadKeys reads the verification keys again and publishes them when the
// issuer and audience are unchanged.
func (c *Controller) ReloadKeys(ctx context.Context, t store.TransitionRecord) (json.RawMessage, int) {
	t.Kind = "keys.reload"
	return c.reloadKeys(ctx, t)
}
