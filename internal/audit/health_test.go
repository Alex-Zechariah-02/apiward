// Audit log health state: recovery does not leave conflicting health flags,
// legal and illegal transitions, terminal failure, and concurrent reads.

package audit

import (
	"context"
	"errors"
	"path/filepath"
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
