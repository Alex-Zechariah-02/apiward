// In-memory permission-use tracking fed by request observations and persisted
// to SQLite by the controller.

package monitor

import (
	"sync"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// PermitUseWindowDays is the sliding window over which unused permissions are
// evaluated and persisted rows are retained.
const PermitUseWindowDays = 30

const permitUseWindow = PermitUseWindowDays * 24 * time.Hour

// PermitSnapshot is an immutable copy of the tracked permission-use window.
type PermitSnapshot struct {
	Since    time.Time
	Requests int
	Used     map[[2]string]time.Time
}

type permitTracker struct {
	mu        sync.Mutex
	permitted map[[2]string]struct{}
	used      map[[2]string]time.Time
	since     time.Time
	requests  int
}

// record marks every verified (role, operation) pair of an admitted request.
func (p *permitTracker) record(event audit.Event) {
	if event.Kind != "request.forwarded" {
		return
	}
	at := event.Time
	if at.IsZero() {
		at = time.Now()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests++
	if p.since.IsZero() || at.Before(p.since) {
		p.since = at
	}
	if p.used == nil {
		p.used = map[[2]string]time.Time{}
	}
	for _, role := range event.Roles {
		pair := [2]string{role, event.Operation}
		if p.permitted != nil {
			if _, ok := p.permitted[pair]; !ok {
				continue
			}
		}
		if prev, ok := p.used[pair]; !ok || at.After(prev) {
			p.used[pair] = at
		}
	}
}

// setPermitted bounds the tracked map to the published policy's permitted pairs.
func (p *permitTracker) setPermitted(g *compile.Generation) {
	if g == nil {
		return
	}
	next := map[[2]string]struct{}{}
	for _, r := range g.Rules() {
		if r.Public() || !r.Permitted() {
			continue
		}
		for _, role := range r.Roles() {
			next[[2]string{role, r.Operation()}] = struct{}{}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.permitted = next
	for pair := range p.used {
		if _, ok := next[pair]; !ok {
			delete(p.used, pair)
		}
	}
}

// load initializes the tracker from persisted state, dropping rows older than
// PermitUseWindowDays.
func (p *permitTracker) load(snap PermitSnapshot, now time.Time) {
	cutoff := now.Add(-permitUseWindow)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.since = snap.Since
	p.requests = snap.Requests
	p.used = map[[2]string]time.Time{}
	for pair, at := range snap.Used {
		if at.Before(cutoff) {
			continue
		}
		if p.permitted != nil {
			if _, ok := p.permitted[pair]; !ok {
				continue
			}
		}
		p.used[pair] = at
	}
}

// snapshot returns a copy of the tracked window, omitting entries older than
// PermitUseWindowDays.
func (p *permitTracker) snapshot(now time.Time) PermitSnapshot {
	cutoff := now.Add(-permitUseWindow)
	p.mu.Lock()
	defer p.mu.Unlock()
	used := make(map[[2]string]time.Time, len(p.used))
	for pair, at := range p.used {
		if !at.Before(cutoff) {
			used[pair] = at
		}
	}
	return PermitSnapshot{Since: p.since, Requests: p.requests, Used: used}
}

// SetPermitted updates the permitted (role, operation) pairs tracked for U1.
func (o *Observations) SetPermitted(g *compile.Generation) { o.permits.setPermitted(g) }

// LoadPermitUse loads persisted permission-use state at startup.
func (o *Observations) LoadPermitUse(snap PermitSnapshot, now time.Time) {
	o.permits.load(snap, now)
}

// PermitUseSnapshot returns a copy of the tracked permission-use state.
func (o *Observations) PermitUseSnapshot(now time.Time) PermitSnapshot {
	return o.permits.snapshot(now)
}
