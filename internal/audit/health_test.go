// Audit log health state: recovery does not leave conflicting health flags,
// legal and illegal transitions, terminal failure, and concurrent reads.

package audit

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A log that transitions between noSpace and down (for example when a retry
// hits a sync error, or when replacing the active file hits ENOSPC) must
// resume writing as soon as replace() succeeds, without leaving noSpace stuck.
func TestAuditReplaceClearsStuckNoSpace(t *testing.T) {
	t.Parallel()
	newIso := func(t *testing.T) *AuditLog {
		t.Helper()
		iso := &AuditLog{
			boot:     "testboot00000001",
			path:     filepath.Join(t.TempDir(), "audit.log"),
			maxBytes: 1 << 20,
			maxFiles: 4,
			queue:    make(chan *auditEntry, AuditQueueSize),
			evictCh:  make(chan *auditEntry, 1),
			done:     make(chan struct{}),
		}
		if _, err := iso.open(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if iso.file != nil {
				_ = iso.file.Close()
			}
		})
		return iso
	}

	t.Run("noSpace_then_down_then_replace", func(t *testing.T) {
		iso := newIso(t)
		iso.replaced = time.Now()
		iso.enterNoSpace(errors.New("enospc"))
		_ = iso.failWrite(errors.New("eio"), "sync_failed")
		if !iso.Failed() {
			t.Fatal("expected log to be failed after enterNoSpace + failWrite")
		}
		iso.replace()
		if iso.Failed() {
			t.Fatal("log stayed Failed() after replace() following noSpace -> down")
		}
	})

	t.Run("down_then_noSpace_then_replace", func(t *testing.T) {
		iso := newIso(t)
		iso.replaced = time.Now()
		_ = iso.failWrite(errors.New("eio"), "sync_failed")
		iso.enterNoSpace(errors.New("enospc"))
		if !iso.Failed() {
			t.Fatal("expected log to be failed after failWrite + enterNoSpace")
		}
		iso.replace()
		if iso.Failed() {
			t.Fatal("log stayed Failed() after replace() following down -> noSpace")
		}
	})
}

// Every state move in the audit health table is accepted and updates health,
// every disallowed move and stale expected state is refused, healthFailed is
// terminal, and concurrent readers observe only valid health states.
func TestAuditHealthTransitions(t *testing.T) {
	t.Parallel()
	allStates := []logHealth{healthWriting, healthFull, healthDown, healthNoSpace, healthFailed}
	allowed := map[[2]logHealth]bool{
		{healthWriting, healthFull}:    true,
		{healthWriting, healthDown}:    true,
		{healthWriting, healthNoSpace}: true,
		{healthWriting, healthFailed}:  true,
		{healthFull, healthWriting}:    true,
		{healthFull, healthDown}:       true,
		{healthFull, healthNoSpace}:    true,
		{healthFull, healthFailed}:     true,
		{healthNoSpace, healthWriting}: true,
		{healthNoSpace, healthDown}:    true,
		{healthNoSpace, healthFailed}:  true,
		{healthDown, healthWriting}:    true,
		{healthDown, healthFailed}:     true,
	}

	for _, from := range allStates {
		for _, to := range allStates {
			a := &AuditLog{}
			a.health.Store(int32(from))
			want := allowed[[2]logHealth{from, to}]
			got := a.moveHealth(from, to)
			if got != want {
				t.Errorf("moveHealth(%d, %d) = %v, want %v", from, to, got, want)
			}
			wantAfter := from
			if want {
				wantAfter = to
			}
			if after := a.currentHealth(); after != wantAfter {
				t.Errorf("after moveHealth(%d, %d): state %d, want %d", from, to, after, wantAfter)
			}
		}
	}

	// Wrong expected state is refused even for a legal edge.
	a := &AuditLog{}
	if a.moveHealth(healthDown, healthWriting) || a.currentHealth() != healthWriting {
		t.Fatalf("wrong expected state succeeded: health=%d", a.currentHealth())
	}
	// Unknown state refuses every transition.
	a.health.Store(99)
	if a.moveHealth(logHealth(99), healthWriting) {
		t.Fatal("unknown state transitioned to healthWriting")
	}

	// failHealth transitions every non-failed state to terminal healthFailed
	// once and returns false once already failed.
	for _, from := range allStates {
		a := &AuditLog{}
		a.health.Store(int32(from))
		want := from != healthFailed
		if got := a.failHealth(); got != want || a.currentHealth() != healthFailed {
			t.Errorf("from %d: failHealth() = %v (want %v), after=%d", from, got, want, a.currentHealth())
		}
		if a.failHealth() {
			t.Errorf("from %d: second failHealth() succeeded", from)
		}
	}

	// Failed() holds for every state except healthWriting.
	for _, s := range allStates {
		a.health.Store(int32(s))
		if got, want := a.Failed(), s != healthWriting; got != want {
			t.Errorf("state %d: Failed() = %v, want %v", s, got, want)
		}
	}

	// Concurrent transitions, terminal failHealth and Failed() reads stay
	// race-free and valid.
	a = &AuditLog{}
	var wg sync.WaitGroup
	var stop atomic.Bool
	for range 4 {
		wg.Go(func() {
			for !stop.Load() {
				s := a.currentHealth()
				_ = a.Failed()
				if s < healthWriting || s > healthFailed {
					t.Errorf("invalid health state %d", s)
					return
				}
			}
		})
	}
	for range 2000 {
		a.moveHealth(healthWriting, healthFull)
		a.moveHealth(healthFull, healthNoSpace)
		a.moveHealth(healthNoSpace, healthDown)
		a.moveHealth(healthDown, healthWriting)
	}
	if !a.failHealth() || a.currentHealth() != healthFailed {
		t.Fatalf("final failHealth failed: state=%d", a.currentHealth())
	}
	stop.Store(true)
	wg.Wait()
}

func BenchmarkAuditHealth(b *testing.B) {
	path := filepath.Join(b.TempDir(), "audit.log")
	a := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 4})
	defer a.Close(context.Background())
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if a.Failed() {
			b.Fatal("healthy audit log read Failed()")
		}
	}
}
