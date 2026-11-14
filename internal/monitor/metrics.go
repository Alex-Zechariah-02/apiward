// Request counters and duration histograms, the listener counters, and the
// metrics listener that exposes them with the published policy gauges.

package monitor

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

var durationBuckets = [...]float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

type metricLabels struct{ api, operation, decision, code string }
type durationMetric struct {
	count   uint64
	sum     float64
	buckets [len(durationBuckets)]uint64
}
type requestMetrics struct {
	counts    map[metricLabels]uint64
	durations map[string]*durationMetric
	apis      int // the policy's API ceiling, which bounds durations
}

// Called under observations.mu. Only compiler-defined identifiers and gateway
// outcome codes reach labels; a hard cap also bounds policy churn over a run.
// Past the cap a new series keeps only its decision: a module's failure
// reason is free text in the code label, so the code collapses too.
func (m *requestMetrics) Record(event RequestView) {
	if m.counts == nil {
		m.counts = map[metricLabels]uint64{}
		m.durations = map[string]*durationMetric{}
	}
	api, operation, code := "unknown", "unknown", ""
	if event.API != nil {
		api = *event.API
	}
	if event.Operation != nil {
		operation = *event.Operation
	}
	if event.Code != nil {
		code = *event.Code
	}
	labels := metricLabels{api, operation, event.Decision, code}
	if _, exists := m.counts[labels]; !exists && len(m.counts) >= 4096 {
		labels.api, labels.operation, labels.code = "unknown", "unknown", "unknown"
	}
	m.counts[labels]++
	if m.durations[api] == nil && len(m.durations) >= m.apis {
		api = "unknown"
	}
	if m.durations[api] == nil {
		m.durations[api] = new(durationMetric)
	}
	duration := m.durations[api]
	duration.count++
	seconds := event.DurationMS / 1000
	duration.sum += seconds
	for i, upper := range durationBuckets {
		if seconds <= upper {
			duration.buckets[i]++
		}
	}
}

// Auxiliary names the listeners besides the data listener, in the order the
// metrics list them.
var Auxiliary = []string{"admin", "metrics", "redirect"}

// Redirected counts one redirect of the HTTP-to-HTTPS redirect listener.
func (o *Observations) Redirected() { o.redirects.Add(1) }

// ConnectionRefused counts one data connection closed at the cap.
func (o *Observations) ConnectionRefused() { o.refused.Add(1) }

// Refuser returns the function that counts one connection closed at the cap
// of listener, one of Auxiliary.
func (o *Observations) Refuser(listener string) func() {
	count := o.auxiliary[listener]
	return func() { count.Add(1) }
}

// Metrics serves the metrics listener from the observations and the
// published gauges, which published reads from the controller.
func Metrics(o *Observations, gauges func() []Gauge) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveMetrics(w, r, o, gauges)
	})
}

// Gauge is one sample the metrics listener reports as read; Counter marks a
// value that only grows, reported with the counter type.
type Gauge struct {
	Name    string
	Value   int64
	Counter bool
}

func serveMetrics(w http.ResponseWriter, r *http.Request, o *Observations, gauges func() []Gauge) {
	if r.Method != "GET" || r.RequestURI != "/metrics" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	// Copy under the lock the request path records under; sort and format
	// after releasing it, so a scrape holds the lock only for the copy.
	o.mu.Lock()
	counts := maps.Clone(o.metrics.counts)
	durations := make(map[string]durationMetric, len(o.metrics.durations))
	for api, duration := range o.metrics.durations {
		durations[api] = *duration
	}
	dropped := o.dropped
	o.mu.Unlock()
	var body strings.Builder
	fmt.Fprintln(&body, "# TYPE gateway_requests_total counter")
	labels := slices.Collect(maps.Keys(counts))
	slices.SortFunc(labels, func(a, b metricLabels) int {
		return strings.Compare(a.api+"\x00"+a.operation+"\x00"+a.decision+"\x00"+a.code, b.api+"\x00"+b.operation+"\x00"+b.decision+"\x00"+b.code)
	})
	for _, label := range labels {
		fmt.Fprintf(&body, "gateway_requests_total{api=%q,operation=%q,decision=%q,code=%q} %d\n", label.api, label.operation, label.decision, label.code, counts[label])
	}
	fmt.Fprintln(&body, "# TYPE gateway_request_duration_seconds histogram")
	for _, api := range slices.Sorted(maps.Keys(durations)) {
		duration := durations[api]
		for i, upper := range durationBuckets {
			fmt.Fprintf(&body, "gateway_request_duration_seconds_bucket{api=%q,le=%q} %d\n", api, strconv.FormatFloat(upper, 'f', -1, 64), duration.buckets[i])
		}
		fmt.Fprintf(&body, "gateway_request_duration_seconds_bucket{api=%q,le=\"+Inf\"} %d\n", api, duration.count)
		fmt.Fprintf(&body, "gateway_request_duration_seconds_sum{api=%q} %g\n", api, duration.sum)
		fmt.Fprintf(&body, "gateway_request_duration_seconds_count{api=%q} %d\n", api, duration.count)
	}
	for _, gauge := range gauges() {
		kind := "gauge"
		if gauge.Counter {
			kind = "counter"
		}
		fmt.Fprintf(&body, "# TYPE %s %s\n%s %d\n", gauge.Name, kind, gauge.Name, gauge.Value)
	}
	fmt.Fprintf(&body, "# TYPE gateway_event_stream_dropped_total counter\ngateway_event_stream_dropped_total %d\n", dropped)
	fmt.Fprintf(&body, "# TYPE gateway_redirects_total counter\ngateway_redirects_total %d\n", o.redirects.Load())
	fmt.Fprintf(&body, "# TYPE gateway_connections_refused_total counter\ngateway_connections_refused_total %d\n", o.refused.Load())
	fmt.Fprintln(&body, "# TYPE gateway_listener_connections_refused_total counter")
	for _, name := range Auxiliary {
		fmt.Fprintf(&body, "gateway_listener_connections_refused_total{listener=%q} %d\n", name, o.auxiliary[name].Load())
	}
	fmt.Fprint(w, body.String())
}
