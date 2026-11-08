// The confirmation deadline's clock rule.

package gateway

import (
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// A provisional generation expires at its deadline on whichever clock
// reaches it first; a confirmed generation never expires. The two clocks are
// set apart here as a wall clock step or a paused monotonic clock would.
// (The test gateway can also move its wall clock alone: see
// TestOverrideExpiryUnderClockChanges.)
func TestDeadlinePredicate(t *testing.T) {
	deadline := time.UnixMilli(time.Now().Add(time.Hour).UnixMilli())
	g, err := compile.Compile(threeAPIPolicy(), 2, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if !g.NotAfter.Equal(deadline) {
		t.Fatalf("NotAfter %v, want %v", g.NotAfter, deadline)
	}
	wall := []struct {
		at      time.Time
		expired bool
	}{
		{deadline.Add(-time.Millisecond), false},
		{deadline, true},
		{deadline.Add(time.Millisecond), true},
	}
	for _, w := range wall {
		if got := g.Expired(w.at); got != w.expired {
			t.Errorf("wall clock %v: expired %v, want %v", w.at, got, w.expired)
		}
	}
	if g.Expired(compile.TrustedNow()) {
		t.Fatal("expired an hour before its deadline")
	}
	if !g.Expired(compile.TrustedNow().Add(time.Hour + time.Second)) {
		t.Fatal("not expired a second after its deadline on both clocks")
	}

	// The trusted time is the later of the wall clock and the monotonic
	// clock's estimate of it, measured from the process start.
	start := compile.ProcessStart.Round(0)
	// The wall clock was set back an hour, but by the monotonic clock the
	// deadline has passed.
	monotonicDeadline := start.Add(2 * time.Hour)
	setBack := &compile.Generation{NotAfter: monotonicDeadline}
	if now := compile.TrustedTime(monotonicDeadline.Add(-time.Hour), 2*time.Hour); !setBack.Expired(now) || !now.Equal(monotonicDeadline) {
		t.Fatalf("a wall clock set back extended the deadline (trusted time %v)", now)
	}
	// The monotonic clock paused (system suspend) while the wall clock moved
	// past the deadline.
	wallDeadline := start.Add(3 * time.Hour)
	suspended := &compile.Generation{NotAfter: wallDeadline}
	if now := compile.TrustedTime(wallDeadline.Add(time.Millisecond), time.Hour); !suspended.Expired(now) || !now.Equal(wallDeadline.Add(time.Millisecond)) {
		t.Fatalf("a paused monotonic clock extended the deadline (trusted time %v)", now)
	}
	// Neither clock has reached the deadline.
	if now := compile.TrustedTime(wallDeadline.Add(-time.Minute), time.Hour); suspended.Expired(now) {
		t.Fatalf("expired before either clock reached the deadline (trusted time %v)", now)
	}
	confirmed, err := compile.Compile(threeAPIPolicy(), 2, time.Time{})
	if err != nil || confirmed.Expired(compile.TrustedNow().Add(1000*time.Hour)) {
		t.Fatalf("a confirmed generation expired: %v", err)
	}
}
