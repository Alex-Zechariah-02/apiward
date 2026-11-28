// Save histograms place each bound and overflow observation in one bucket.

package audit

import (
	"testing"
	"time"
)

func TestSaveHistogramCoversBoundsAndOverflow(t *testing.T) {
	t.Parallel()
	var log AuditLog
	bounds := log.Saves().Bounds
	if len(bounds) == 0 {
		t.Fatal("save histogram has no bounds")
	}
	var total time.Duration
	var slow int64
	for _, upper := range bounds {
		wait := time.Duration(upper * float64(time.Second))
		log.saves.observe(wait)
		total += wait
		if wait >= SlowSave {
			slow++
		}
	}
	last := time.Duration(bounds[len(bounds)-1] * float64(time.Second))
	log.saves.observe(last + time.Nanosecond)
	total += last + time.Nanosecond
	if last+time.Nanosecond >= SlowSave {
		slow++
	}
	got := log.Saves()
	if got.Sum != total.Seconds() {
		t.Errorf("histogram sum is %g seconds, want %g", got.Sum, total.Seconds())
	}
	if got.Slow != slow {
		t.Errorf("histogram counted %d slow saves, want %d", got.Slow, slow)
	}
	if got.Count != uint64(len(bounds)+1) {
		t.Fatalf("histogram counted %d observations, want %d", got.Count, len(bounds)+1)
	}
	if len(got.Buckets) != len(bounds)+1 {
		t.Fatalf("histogram has %d counters for %d bounds", len(got.Buckets), len(bounds))
	}
	for bucket, count := range got.Buckets {
		if count != 1 {
			t.Errorf("bucket %d counted %d observations, want one", bucket, count)
		}
	}
}
