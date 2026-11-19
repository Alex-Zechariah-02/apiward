package monitor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
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

// A request view says when its path was cut: for a live event that still
// holds the whole path and for a record read back already cut, never for a
// whole path.
func TestViewMarksCutPath(t *testing.T) {
	whole := "/a/" + strings.Repeat("x", audit.MaxLoggedPath-3)
	for _, tc := range []struct {
		name  string
		event audit.Event
		want  bool
	}{
		{"live long path", audit.Event{Path: whole + "/tail"}, true},
		{"stored cut path", audit.Event{Path: whole, Truncated: true}, true},
		{"path of exactly the bound", audit.Event{Path: whole}, false},
		{"short path", audit.Event{Path: "/a/x"}, false},
	} {
		view := View(tc.event)
		if view.Truncated != tc.want || len(view.Path) > audit.MaxLoggedPath {
			t.Errorf("%s: truncated = %v (path %d bytes), want %v", tc.name, view.Truncated, len(view.Path), tc.want)
		}
	}
}

// A view keeps the gateway's own failure apart from a refusal and from an
// upstream failure, and names the upstream and the rewritten path.
func TestViewDecisionsAndDestination(t *testing.T) {
	for recorded, want := range map[string]string{"forwarded": "allowed", "allowed": "allowed", "reject": "refused", "refused": "refused", "failed": "failed", "upstream_failure": "upstream_failed"} {
		if got := View(audit.Event{Decision: recorded}).Decision; got != want {
			t.Errorf("%s: decision %s, want %s", recorded, got, want)
		}
	}
	view := View(audit.Event{Decision: "forwarded", Upstream: "orders", ForwardedPath: "/v2/x", Roles: []string{"B"}, IgnoredRoles: []string{"A"}})
	if view.Upstream == nil || *view.Upstream != "orders" || view.ForwardedPath == nil || *view.ForwardedPath != "/v2/x" || !slices.Equal(view.Roles, []string{"B"}) {
		t.Fatalf("view: %+v", view)
	}
	if view := View(audit.Event{}); view.Upstream != nil || view.ForwardedPath != nil || view.Roles == nil {
		t.Fatalf("empty view: %+v", view)
	}
}

// recent returns exactly what filtering a full snapshot the same way
// returns, newest first, up to its limit, after the ring has wrapped.
func TestRecentObservationsMatchSnapshotFiltering(t *testing.T) {
	o := New(policy.DefaultWindow, policy.DefaultAPIs)
	end := time.Now().UTC()
	fillObservations(o, policy.DefaultWindow+137, end)
	var all []Entry
	o.Walk(time.Time{}, func(e *Entry) bool {
		all = append(all, *e)
		return true
	})
	cursor := all[500].Sequence()
	for _, tc := range []struct {
		name  string
		keep  func(*Entry) bool
		limit int
	}{
		{"everything", func(*Entry) bool { return true }, 0},
		{"the last minute", func(r *Entry) bool { return !r.Time.Before(end.Add(-time.Minute)) }, 0},
		{"one subject, one page", func(r *Entry) bool { return r.Subject == "user-3" }, 21},
		{"refused before a cursor", func(r *Entry) bool { return r.Decision == "refused" && r.Sequence() < cursor }, 51},
		{"nothing", func(r *Entry) bool { return r.RequestID == "absent" }, 5},
		// With no limit, requests the filter skips before the first match
		// end nothing: the newest one here is outside the window.
		{"all but the newest, no limit", func(r *Entry) bool { return r.Sequence() != all[0].Sequence() }, 0},
		{"older than a cursor, no limit", func(r *Entry) bool { return r.Sequence() < cursor }, 0},
	} {
		var want []Entry
		for i := range all {
			if tc.keep(&all[i]) {
				want = append(want, all[i])
				if len(want) == tc.limit {
					break
				}
			}
		}
		got := o.Recent(tc.keep, tc.limit)
		same := func(a Observed, b Entry) bool { return a.RequestID == b.RequestID && a.Sequence() == b.Sequence() }
		if !slices.EqualFunc(got, want, same) {
			t.Errorf("%s: recent returned %d requests, filtering the snapshot %d", tc.name, len(got), len(want))
		}
	}
}

// BenchmarkObservationWindowRead compares reading a one-minute window of a
// full ring by copying every retained request (the former traffic read)
// with copying only the requests in the window. Diagnostic only.
func BenchmarkObservationWindowRead(b *testing.B) {
	o := New(policy.DefaultWindow, policy.DefaultAPIs)
	end := time.Now().UTC()
	fillObservations(o, policy.DefaultWindow, end)
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
			if n := len(o.Recent(func(r *Entry) bool { return !r.Time.Before(start) }, 0)); n != 61 {
				b.Fatalf("%d requests in the window", n)
			}
		}
	})
}

// A traffic comparison needs to know whether the ring still holds every
// request back to the start of the earlier window.
func TestRetainedSinceReportsDroppedRequests(t *testing.T) {
	o := New(policy.DefaultWindow, policy.DefaultAPIs)
	if _, dropped := o.RetainedSince(); dropped {
		t.Fatal("an empty ring reports dropped requests")
	}
	end := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	fillObservations(o, policy.DefaultWindow, end)
	oldest, dropped := o.RetainedSince()
	if dropped || !oldest.Equal(end.Add(-time.Duration(policy.DefaultWindow-1)*time.Second)) {
		t.Fatalf("full ring: oldest %v, dropped %v", oldest, dropped)
	}
	fillObservations(o, 1, end.Add(time.Second))
	oldest, dropped = o.RetainedSince()
	if !dropped || !oldest.Equal(end.Add(-time.Duration(policy.DefaultWindow-2)*time.Second)) {
		t.Fatalf("after one more: oldest %v, dropped %v", oldest, dropped)
	}
}

// A time-bounded walk visits every request at or after its start, also one
// that ended after newer requests and so sits among them in the window, and
// stops soon after: it does not read the whole window.
func TestWalkFromVisitsLateRequests(t *testing.T) {
	o := New(policy.DefaultWindow, policy.DefaultAPIs)
	end := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	fillObservations(o, 5000, end.Add(-time.Hour))
	// Requests one second apart in the last minute; the one stamped at the
	// minute's start ended 30 seconds late.
	for i := range 60 {
		at := end.Add(time.Duration(i-59) * time.Second)
		o.Record(audit.Event{RequestID: fmt.Sprint(i), Time: at, Decision: "forwarded"})
		if i == 30 {
			o.Record(audit.Event{RequestID: "late", Time: end.Add(-time.Minute), Decision: "forwarded"})
		}
	}
	from := end.Add(-time.Minute)
	seen, inside, late := 0, 0, false
	o.Walk(from, func(e *Entry) bool {
		seen++
		if !e.Time.Before(from) {
			inside++
			late = late || e.RequestID == "late"
		}
		return true
	})
	if inside != 61 || !late {
		t.Fatalf("visited %d requests from the start, late one %t; want 61 with it", inside, late)
	}
	if seen > 61+readBatch {
		t.Fatalf("visited %d requests: the walk did not stop near its start", seen)
	}
}

// Past the series cap a new series keeps only its decision, and the requests
// it counts are reported; a module failure's free-text reason never becomes
// a label: it is counted as gateway_unavailable with the module named.
func TestMetricsSeriesCap(t *testing.T) {
	m := requestMetrics{apis: 1}
	for i := range 4200 {
		m.Record(audit.Event{Decision: "reject", Operation: fmt.Sprintf("op%d", i), Error: "forbidden"})
	}
	if len(m.series) != 4097 || m.collapsed != 104 {
		t.Fatalf("%d series, %d collapsed; want the 4,096 cap plus one collapsed series counting 104", len(m.series), m.collapsed)
	}
	for _, tc := range []struct{ code, label, module string }{
		{"forbidden", "forbidden", ""},
		{"module geo: lookup \"down\"", "gateway_unavailable", "geo"},
		{"module Bad Id: x", "gateway_unavailable", "unknown"},
		{"Not A Code", "unknown", ""},
		{"", "", ""},
	} {
		if label, module := codeLabel(tc.code); label != tc.label || module != tc.module {
			t.Errorf("%q: label %q module %q, want %q %q", tc.code, label, module, tc.label, tc.module)
		}
	}
}

// The exposition escapes label values as the text format reads them, and the
// gateway's overhead and the upstream's time are split from forwarded requests.
func TestMetricsExposition(t *testing.T) {
	o := New(10, 2)
	o.Record(audit.Event{API: "a\"b\\c\nd", Operation: "x", Decision: "forwarded", DurationMS: 3, UpstreamMS: 2})
	reply := httptest.NewRecorder()
	Metrics(o, func() []Gauge { return nil }).ServeHTTP(reply, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := reply.Body.String()
	for _, want := range []string{
		`gateway_requests_total{api="a\"b\\c\nd",operation="x",decision="allowed"} 1`,
		`apiward_upstream_seconds_bucket{api="a\"b\\c\nd",le="0.0025"} 1`,
		`apiward_upstream_seconds_bucket{api="a\"b\\c\nd",le="0.001"} 0`,
		`apiward_gateway_overhead_seconds_bucket{api="a\"b\\c\nd",le="0.001"} 1`,
		`gateway_request_duration_seconds_bucket{api="a\"b\\c\nd",le="0.0025"} 0`,
		`gateway_request_duration_seconds_bucket{api="a\"b\\c\nd",le="0.005"} 1`,
		"gateway_recent_requests 1\n",
		"gateway_metric_series_dropped_total 0\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("exposition lacks %s", want)
		}
	}
}
