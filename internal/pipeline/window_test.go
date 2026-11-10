// The sliding-window counter against reference vectors, a reference model
// and clock movement.

package pipeline

import (
	"math/big"
	"math/rand/v2"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// step is one call of the limiter at a time with its expected decision.
type step struct {
	at    int64 // milliseconds
	admit bool
}

func runSteps(t *testing.T, name string, l *Limiter, key counterKey, rule *compile.RateRule, steps []step) {
	t.Helper()
	for i, s := range steps {
		got := l.admit(key, rule, s.at) == rateAdmitted
		if got != s.admit {
			t.Fatalf("%s step %d at %d ms: admitted %v, want %v", name, i, s.at, got, s.admit)
		}
	}
}

func repeatStep(n int, at int64, admit bool) []step {
	steps := make([]step, n)
	for i := range steps {
		steps[i] = step{at, admit}
	}
	return steps
}

// Hand-computed vectors for the rule: admit when C + P*(W-d)/W + 1 <= N,
// where C and P count admitted requests in the current and previous bucket
// and d is the offset into the current bucket. Each expected value is
// worked out in the comment beside it, not taken from the implementation.
func TestSlidingWindowReferenceVectors(t *testing.T) {
	key := counterKey{"op", "subject", "alice"}

	// N=10, W=60 s, buckets start at multiples of 60 000 ms.
	l := NewLimiter(policy.DefaultRateCounters)
	rule := quota(10, 60000)
	var steps []step
	steps = append(steps, repeatStep(10, 1000, true)...)   // bucket 0, fresh: the first 10 are admitted
	steps = append(steps, repeatStep(5, 2000, false)...)   // C=10: refused, and refusals are not counted
	steps = append(steps, step{60000, false})              // bucket 1, d=0: P=10, E = 10; 11 > 10
	steps = append(steps, repeatStep(5, 90000, true)...)   // d=30 s: E = C + 10*0.5; C+5+1 <= 10 for C = 0..4
	steps = append(steps, step{90000, false})              // C=5: 5+5+1 = 11 > 10
	steps = append(steps, step{96000, true})               // d=36 s: E = 5 + 10*0.4 = 9; 10 <= 10, equality admits
	steps = append(steps, step{96000, false})              // C=6: 6+4+1 = 11 > 10
	steps = append(steps, repeatStep(3, 119999, true)...)  // d=59.999 s: E = C + 10/60000; C+1.0002 <= 10 for C = 6..8
	steps = append(steps, step{119999, false})             // C=9: 10.0002 > 10
	steps = append(steps, step{120000, true})              // bucket 2, d=0: P=9, E = 9; 10 <= 10
	steps = append(steps, step{120000, false})             // C=1: 11 > 10
	steps = append(steps, repeatStep(10, 240000, true)...) // bucket 4 is two after bucket 2: nothing remains
	steps = append(steps, step{240000, false})
	runSteps(t, "N=10", l, key, rule, steps)

	// N=3, W=1 s: fractional weights at the equality boundary.
	l = NewLimiter(policy.DefaultRateCounters)
	rule = quota(3, 1000)
	runSteps(t, "N=3", l, key, rule, []step{
		{0, true}, {500, true}, {999, true}, {999, false}, // bucket 0 fills
		{1500, true},  // bucket 1, d=500: P=3, E = 1.5; 2.5 <= 3
		{1500, false}, // C=1: 1 + 1.5 + 1 = 3.5 > 3
		{1667, true},  // d=667: E = 1 + 3*0.333 = 1.999; 2.999 <= 3
		{1667, false}, // C=2: 2 + 0.999 + 1 > 3
		{1999, false}, // d=999: E = 2 + 3*0.001 = 2.003; 3.003 > 3
		{2000, true},  // bucket 2, d=0: P=2 (bucket 1 admitted two), E = 2; 3 <= 3
		{2000, false}, // C=1: 1 + 2 + 1 = 4 > 3
		{2334, false}, // d=334: E = 1 + 2*0.666 = 2.332; 3.332 > 3
		{2667, true},  // d=667: E = 1 + 2*0.333 = 1.666; 2.666 <= 3
		{2667, false}, // C=2: 2 + 0.666 + 1 > 3
	})

	// N=1, W=1 s: one request per bucket at most, and exactly at the
	// boundary the previous request still weighs fully.
	l = NewLimiter(policy.DefaultRateCounters)
	rule = quota(1, 1000)
	runSteps(t, "N=1", l, key, rule, []step{
		{10, true}, {999, false},
		{1000, false}, // d=0: E = 1; 2 > 1
		{1001, false}, // d=1: E = 0.999; 1.999 > 1
		{2000, true},  // previous bucket empty: E = 0
	})
}

// referenceAdmit is an independent model of the documented rule, written from
// its text with rational arithmetic and its own bucket bookkeeping.
type referenceCounter struct {
	bucket            int64
	current, previous int64
	started           bool
}

func (m *referenceCounter) admit(n, w, now int64) bool {
	bucket := now / w
	if !m.started {
		m.bucket, m.started = bucket, true
	}
	switch gap := bucket - m.bucket; {
	case gap == 1:
		m.previous, m.current, m.bucket = m.current, 0, bucket
	case gap > 1:
		m.previous, m.current, m.bucket = 0, 0, bucket
	}
	offset := max(now-m.bucket*w, 0)
	estimate := new(big.Rat).SetInt64(m.current)
	weight := big.NewRat(w-offset, w)
	estimate.Add(estimate, new(big.Rat).Mul(big.NewRat(m.previous, 1), weight))
	estimate.Add(estimate, big.NewRat(1, 1))
	if estimate.Cmp(big.NewRat(n, 1)) > 0 {
		return false
	}
	m.current++
	return true
}

// The limiter agrees with the reference model on random request sequences
// with fixed seeds, across several quotas and windows.
func TestSlidingWindowAgainstReferenceModel(t *testing.T) {
	configs := []struct{ n, w int64 }{{1, 1000}, {3, 1000}, {7, 10000}, {10, 60000}, {100, 3600000}, {compile.MaxRateCount, compile.MaxRateWindowSec * 1000}}
	for _, c := range configs {
		for seed := uint64(1); seed <= 5; seed++ {
			random := rand.New(rand.NewPCG(seed, uint64(c.n)))
			l := NewLimiter(policy.DefaultRateCounters)
			rule := quota(c.n, c.w)
			key := counterKey{"op", "subject", "s"}
			var model referenceCounter
			now := int64(1_700_000_000_000)
			for i := range 5000 {
				// Mostly small steps, sometimes a jump of up to three windows.
				if random.IntN(50) == 0 {
					now += random.Int64N(3 * c.w)
				} else {
					now += random.Int64N(c.w/max(c.n, 1)/2 + 1)
				}
				want := model.admit(c.n, c.w, now)
				if got := l.admit(key, rule, now) == rateAdmitted; got != want {
					t.Fatalf("N=%d W=%d seed %d request %d at %d: limiter %v, reference %v", c.n, c.w, seed, i, now, got, want)
				}
			}
		}
	}
}

// A clock that moves backwards never forgives requests: the previous bucket
// then weighs fully. A forward jump only ages counts as real time would.
func TestClockMovementNeverGrantsExtraQuota(t *testing.T) {
	l := NewLimiter(policy.DefaultRateCounters)
	rule := quota(3, 1000)
	key := counterKey{"op", "subject", "alice"}
	runSteps(t, "clock", l, key, rule, []step{
		{5000, true}, {5100, true}, {5200, true}, {5300, false}, // bucket 5 fills
		{4000, false},                                           // backwards into bucket 4: bucket 5 is kept, E = 3
		{0, false},                                              // far backwards: the same
		{6500, true},                                            // bucket 6, d=500: P=3, E = 1.5; 2.5 <= 3
		{6500, false},                                           // C=1: 3.5 > 3
		{6000, false},                                           // d=0: E = 1 + 3; refused
		{5999, false},                                           // backwards before bucket 6: d taken as 0, E = 4
		{9000, true}, {9000, true}, {9000, true}, {9000, false}, // a forward jump past two buckets: fresh
	})
}
