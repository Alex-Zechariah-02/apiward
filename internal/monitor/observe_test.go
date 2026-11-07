package monitor

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// fillObservations records n requests one second apart, the last at end,
// with subjects and decisions varying so filters select different subsets.
func fillObservations(o *Observations, n int, end time.Time) {
	for i := range n {
		decision := "forwarded"
		if i%3 == 0 {
			decision = "rejected"
		}
		o.Record(audit.Event{RequestID: fmt.Sprintf("req-%05d", i), Time: end.Add(time.Duration(i-n+1) * time.Second),
			Method: "GET", Path: "/a/x", Operation: "a.read", API: "a", Subject: fmt.Sprintf("user-%d", i%7),
			Decision: decision, Stage: "FORWARD", Status: 200})
	}
}

// recent returns exactly what filtering a full snapshot the same way
// returns, newest first, up to its limit, after the ring has wrapped.
func TestRecentObservationsMatchSnapshotFiltering(t *testing.T) {
	o := New()
	end := time.Now().UTC()
	fillObservations(o, RecentLimit+137, end)
	all := o.Snapshot()
	cursor := all[500].Sequence()
	for _, tc := range []struct {
		name  string
		keep  func(*Observed) bool
		limit int
	}{
		{"everything", func(*Observed) bool { return true }, 0},
		{"the last minute", func(r *Observed) bool { return !r.Time.Before(end.Add(-time.Minute)) }, 0},
		{"one subject, one page", func(r *Observed) bool { return r.Subject != nil && *r.Subject == "user-3" }, 21},
		{"refused before a cursor", func(r *Observed) bool { return r.Decision == "refused" && r.Sequence() < cursor }, 51},
		{"nothing", func(r *Observed) bool { return r.RequestID == "absent" }, 5},
	} {
		var want []Observed
		for i := range all {
			if tc.keep(&all[i]) {
				want = append(want, all[i])
				if len(want) == tc.limit {
					break
				}
			}
		}
		got := o.Recent(tc.keep, tc.limit)
		same := func(a, b Observed) bool { return a.RequestID == b.RequestID && a.Sequence() == b.Sequence() }
		if !slices.EqualFunc(got, want, same) {
			t.Errorf("%s: recent returned %d requests, filtering the snapshot %d", tc.name, len(got), len(want))
		}
	}
}

// BenchmarkObservationWindowRead compares reading a one-minute window of a
// full ring by copying every retained request (the former traffic read)
// with copying only the requests in the window. Diagnostic only.
func BenchmarkObservationWindowRead(b *testing.B) {
	o := New()
	end := time.Now().UTC()
	fillObservations(o, RecentLimit, end)
	start := end.Add(-time.Minute)
	b.Run("snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			n := 0
			for _, r := range o.Snapshot() {
				if !r.Time.Before(start) {
					n++
				}
			}
			if n != 61 {
				b.Fatalf("%d requests in the window", n)
			}
		}
	})
	b.Run("recent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if n := len(o.Recent(func(r *Observed) bool { return !r.Time.Before(start) }, 0)); n != 61 {
				b.Fatalf("%d requests in the window", n)
			}
		}
	})
}

// A traffic comparison needs to know whether the ring still holds every
// request back to the start of the earlier window.
func TestRetainedSinceReportsDroppedRequests(t *testing.T) {
	o := New()
	if _, dropped := o.RetainedSince(); dropped {
		t.Fatal("an empty ring reports dropped requests")
	}
	end := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	fillObservations(o, RecentLimit, end)
	oldest, dropped := o.RetainedSince()
	if dropped || !oldest.Equal(end.Add(-time.Duration(RecentLimit-1)*time.Second)) {
		t.Fatalf("full ring: oldest %v, dropped %v", oldest, dropped)
	}
	fillObservations(o, 1, end.Add(time.Second))
	oldest, dropped = o.RetainedSince()
	if !dropped || !oldest.Equal(end.Add(-time.Duration(RecentLimit-2)*time.Second)) {
		t.Fatalf("after one more: oldest %v, dropped %v", oldest, dropped)
	}
}
