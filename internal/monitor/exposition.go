// The metrics listener's answer: the request counters and histograms, the
// window and live views, the listener counters and the published gauges, in
// the Prometheus text format.

package monitor

import (
	"cmp"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Metrics serves the metrics listener from the observations and the
// published gauges, which published reads from the controller.
func Metrics(o *Observations, gauges func() []Gauge) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveMetrics(w, r, o, gauges)
	})
}

// Gauge is one sample the metrics listener reports as read; Counter marks a
// value that only grows, reported with the counter type. Labels are name and
// value pairs, such as the value of an info metric (Value 1). Samples of one
// name are listed together. Spread, when set, makes it a histogram instead.
type Gauge struct {
	Name    string
	Value   int64
	Counter bool
	Labels  []string
	Spread  *Spread
}

// Spread is a histogram: counts per bucket of Bounds (not cumulative; one
// more for values above every bound), the count and the sum in seconds.
type Spread struct {
	Bounds  []float64
	Buckets []uint64
	Count   uint64
	Sum     float64
}

// exposition writes the text format. Label values are escaped as the format
// requires (backslash, double quote, line feed); invalid UTF-8 is replaced.
type exposition struct{ text strings.Builder }

func (b *exposition) family(name, kind string) {
	b.text.WriteString("# TYPE " + name + " " + kind + "\n")
}

// sample writes one line; labels are name and value pairs, and a pair with
// an empty value is left out, which the format reads as the same series.
func (b *exposition) sample(name string, value string, labels ...string) {
	b.text.WriteString(name)
	open := false
	for i := 0; i+1 < len(labels); i += 2 {
		if labels[i+1] == "" {
			continue
		}
		if open {
			b.text.WriteByte(',')
		} else {
			b.text.WriteByte('{')
			open = true
		}
		b.text.WriteString(labels[i] + "=" + `"` + escapeLabel(labels[i+1]) + `"`)
	}
	if open {
		b.text.WriteByte('}')
	}
	b.text.WriteString(" " + value + "\n")
}

var labelEscapes = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escapeLabel(value string) string {
	return labelEscapes.Replace(strings.ToValidUTF8(value, string(utf8.RuneError)))
}

func count(n uint64) string { return strconv.FormatUint(n, 10) }

func seconds(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

func (b *exposition) histogram(name, api string, bounds []float64, h histogram) {
	var total uint64
	for i, upper := range bounds {
		if h.buckets != nil {
			total += h.buckets[i]
		}
		b.sample(name+"_bucket", count(total), "api", api, "le", strconv.FormatFloat(upper, 'f', -1, 64))
	}
	b.sample(name+"_bucket", count(h.count), "api", api, "le", "+Inf")
	b.sample(name+"_sum", seconds(h.sum), "api", api)
	b.sample(name+"_count", count(h.count), "api", api)
}

func serveMetrics(w http.ResponseWriter, r *http.Request, o *Observations, gauges func() []Gauge) {
	if r.Method != "GET" || r.RequestURI != "/metrics" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	// Copy under the metrics' own lock; sort and format after releasing it.
	counts, times, collapsed := o.metrics.read()
	var b exposition
	b.family("gateway_requests_total", "counter")
	slices.SortFunc(counts, func(x, y series) int {
		return cmp.Or(strings.Compare(x.labels.api, y.labels.api), strings.Compare(x.labels.operation, y.labels.operation),
			strings.Compare(x.labels.decision, y.labels.decision), strings.Compare(x.labels.code, y.labels.code), strings.Compare(x.labels.module, y.labels.module))
	})
	for _, s := range counts {
		b.sample("gateway_requests_total", count(s.count), "api", s.labels.api, "operation", s.labels.operation, "decision", s.labels.decision, "code", s.labels.code, "module", s.labels.module)
	}
	slices.SortFunc(times, func(x, y apiTimes) int { return strings.Compare(x.api, y.api) })
	for _, family := range []struct {
		name   string
		bounds []float64
		pick   func(apiTimes) histogram
	}{
		{"gateway_request_duration_seconds", requestBuckets, func(t apiTimes) histogram { return t.request }},
		{"apiward_gateway_overhead_seconds", splitBuckets, func(t apiTimes) histogram { return t.overhead }},
		{"apiward_upstream_seconds", splitBuckets, func(t apiTimes) histogram { return t.upstream }},
	} {
		b.family(family.name, "histogram")
		for _, t := range times {
			b.histogram(family.name, t.api, family.bounds, family.pick(t))
		}
	}
	b.family("gateway_metric_series_dropped_total", "counter")
	b.sample("gateway_metric_series_dropped_total", count(collapsed))
	previous := ""
	for _, gauge := range gauges() {
		if gauge.Spread != nil {
			b.family(gauge.Name, "histogram")
			b.histogram(gauge.Name, "", gauge.Spread.Bounds, histogram{buckets: gauge.Spread.Buckets, count: gauge.Spread.Count, sum: gauge.Spread.Sum})
			continue
		}
		kind := "gauge"
		if gauge.Counter {
			kind = "counter"
		}
		if gauge.Name != previous {
			b.family(gauge.Name, kind)
		}
		previous = gauge.Name
		b.sample(gauge.Name, strconv.FormatInt(gauge.Value, 10), gauge.Labels...)
	}
	o.window(&b)
	for _, counter := range []struct {
		name  string
		value uint64
	}{
		{"gateway_event_stream_dropped_total", o.dropped.Load()},
		{"gateway_redirects_total", o.redirects.Load()},
		{"gateway_connections_refused_total", o.refused.Load()},
		{"gateway_http2_errors_total", o.http2.Load()},
	} {
		b.family(counter.name, "counter")
		b.sample(counter.name, count(counter.value))
	}
	b.family("gateway_listener_connections_refused_total", "counter")
	for _, name := range Auxiliary {
		b.sample("gateway_listener_connections_refused_total", count(o.auxiliary[name].Load()), "listener", name)
	}
	b.family("gateway_admin_failures_total", "counter")
	for f := range adminFailures {
		b.sample("gateway_admin_failures_total", count(o.admin[f].Load()), "reason", f.String())
	}
	b.family("gateway_key_reload_failures_total", "counter")
	b.sample("gateway_key_reload_failures_total", count(o.keyReloads.Load()))
	_, _ = w.Write([]byte(b.text.String()))
}

// window writes the state of the window of recent requests and the live
// views: how many requests it keeps, the age of the oldest, and the views open.
func (o *Observations) window(b *exposition) {
	oldest, _ := o.RetainedSince()
	age := 0.0
	if !oldest.IsZero() {
		age = max(time.Since(oldest).Seconds(), 0)
	}
	b.family("gateway_recent_requests", "gauge")
	b.sample("gateway_recent_requests", strconv.Itoa(o.Retained()))
	b.family("gateway_window_oldest_seconds", "gauge")
	b.sample("gateway_window_oldest_seconds", seconds(age))
	b.family("gateway_live_views", "gauge")
	b.sample("gateway_live_views", strconv.Itoa(o.Viewers()))
}
