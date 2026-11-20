// Save waits: how long each acknowledged record waited for the sync that
// covers it, as a histogram for the metrics listener, a count of slow saves
// and at most one log line a minute naming them, so a slow disk is seen
// before the save wait (gateway.audit_timeout) starts refusing requests.

package audit

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// SaveBounds are the histogram's upper bounds in seconds: the gateway
// overhead buckets plus 0.5 s and 2 s, the default save wait.
var SaveBounds = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1, 0.5, 1, 2, 10}

// SlowSave is the wait from which a save counts as slow: a hundred times a
// typical synced write, a twentieth of the default save wait.
const SlowSave = 100 * time.Millisecond

// slowReport bounds the slow-save log lines to one a minute.
const slowReport = time.Minute

// saves is the histogram; buckets count waits up to each bound, the last
// place those above every bound.
type saves struct {
	buckets [14]atomic.Uint64
	count   atomic.Uint64
	nanos   atomic.Uint64
	slow    atomic.Int64
	mu      sync.Mutex // guards the report below
	since   time.Time
	pending uint64
	longest time.Duration
}

// observe records one wait.
func (s *saves) observe(wait time.Duration) {
	at := len(SaveBounds)
	for i, bound := range SaveBounds {
		if wait.Seconds() <= bound {
			at = i
			break
		}
	}
	s.buckets[at].Add(1)
	s.count.Add(1)
	s.nanos.Add(uint64(max(wait, 0)))
	if wait < SlowSave {
		return
	}
	s.slow.Add(1)
	s.report(wait)
}

// report logs the slow saves seen, at most once per slowReport.
func (s *saves) report(wait time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending++
	s.longest = max(s.longest, wait)
	now := time.Now()
	if now.Sub(s.since) < slowReport {
		return
	}
	slog.Warn("security log saves are slow", "count", s.pending, "longest", s.longest.String(), "threshold", SlowSave.String())
	s.since, s.pending, s.longest = now, 0, 0
}

// SaveTimes is the histogram: the count per bucket of SaveBounds (not
// cumulative; the last entry counts waits above every bound), the number of
// waits, their sum in seconds and the slow ones.
type SaveTimes struct {
	Buckets []uint64
	Count   uint64
	Sum     float64
	Slow    int64
}

// Saves reads the histogram.
func (a *AuditLog) Saves() SaveTimes {
	s := &a.saves
	t := SaveTimes{Buckets: make([]uint64, len(s.buckets)), Count: s.count.Load(), Slow: s.slow.Load()}
	for i := range s.buckets {
		t.Buckets[i] = s.buckets[i].Load()
	}
	t.Sum = float64(s.nanos.Load()) / float64(time.Second)
	return t
}
