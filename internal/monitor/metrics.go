// Request counters and duration histograms, recorded per request under
// their own lock, and the listener and Admin API counters.

package monitor

import (
	"strings"
	"sync"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// requestBuckets are the Prometheus client libraries' default buckets with
// a finer low end, as most gateway decisions take well under a millisecond.
var requestBuckets = []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// splitBuckets resolve the gateway's own time and the upstream's from 0.1 ms
// to 10 s.
var splitBuckets = []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .1, 1, 10}

// maxSeries bounds the request counter series: only compiler-defined
// identifiers and gateway outcome codes reach labels, and the cap also
// bounds policy churn over a run.
const maxSeries = 4096

type metricLabels struct{ api, operation, decision, code, module string }

type series struct {
	labels metricLabels
	count  uint64
}

// histogram counts observations per bucket (not cumulative; the exposition
// sums them) and beyond the last bucket.
type histogram struct {
	count   uint64
	sum     float64
	buckets []uint64
}

func (h *histogram) observe(bounds []float64, seconds float64) {
	if h.buckets == nil {
		h.buckets = make([]uint64, len(bounds))
	}
	h.count++
	h.sum += seconds
	for i, upper := range bounds {
		if seconds <= upper {
			h.buckets[i]++
			return
		}
	}
}

// apiTimes are one API's request, gateway-overhead and upstream histograms.
type apiTimes struct {
	api                         string
	request, overhead, upstream histogram
}

// requestMetrics keeps series in slices with a map index, so a scrape copies
// them without hashing; its own lock keeps a scrape off the window's lock.
type requestMetrics struct {
	mu        sync.Mutex
	index     map[metricLabels]int
	series    []series
	timeIndex map[string]int
	times     []apiTimes
	apis      int    // the policy's API ceiling, which bounds the histograms
	collapsed uint64 // requests counted in a collapsed series past the cap
}

// Record counts one request's final event. Past the series cap a new series
// keeps only its decision and code class.
func (m *requestMetrics) Record(event audit.Event) {
	api, operation := event.API, event.Operation
	if api == "" {
		api = "unknown"
	}
	if operation == "" {
		operation = "unknown"
	}
	code, module := codeLabel(event.Error)
	labels := metricLabels{api, operation, decision(event.Decision), code, module}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.index == nil {
		m.index, m.timeIndex = map[metricLabels]int{}, map[string]int{}
	}
	i, exists := m.index[labels]
	if !exists && len(m.series) >= maxSeries {
		labels = metricLabels{"unknown", "unknown", labels.decision, "unknown", ""}
		m.collapsed++
		i, exists = m.index[labels]
	}
	if !exists {
		i = len(m.series)
		m.index[labels] = i
		m.series = append(m.series, series{labels: labels})
	}
	m.series[i].count++
	t, exists := m.timeIndex[api]
	if !exists && len(m.times) >= m.apis {
		api = "unknown"
		t, exists = m.timeIndex[api]
	}
	if !exists {
		t = len(m.times)
		m.timeIndex[api] = t
		m.times = append(m.times, apiTimes{api: api})
	}
	times := &m.times[t]
	times.request.observe(requestBuckets, event.DurationMS/1000)
	if event.UpstreamMS > 0 {
		times.upstream.observe(splitBuckets, event.UpstreamMS/1000)
		times.overhead.observe(splitBuckets, max(event.DurationMS-event.UpstreamMS, 0)/1000)
	}
}

// codeLabel keeps the code label to the gateway's outcome codes and module
// refusal codes, all short tokens. A module failure's free-text reason
// becomes gateway_unavailable, the code its client was answered, with the
// module named; any other text becomes unknown.
func codeLabel(code string) (label, module string) {
	if rest, ok := strings.CutPrefix(code, "module "); ok {
		id, _, found := strings.Cut(rest, ": ")
		if !found || !token(id) {
			id = "unknown"
		}
		return "gateway_unavailable", id
	}
	if code == "" || token(code) {
		return code, ""
	}
	return "unknown", ""
}

// token is the form of every outcome code: a lowercase letter, then at most
// 63 lowercase letters, digits or underscores.
func token(text string) bool {
	if text == "" || len(text) > 64 || text[0] < 'a' || text[0] > 'z' {
		return false
	}
	for i := range len(text) {
		c := text[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// read copies the series for a scrape.
func (m *requestMetrics) read() ([]series, []apiTimes, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	times := make([]apiTimes, len(m.times))
	for i, t := range m.times {
		times[i] = apiTimes{api: t.api, request: t.request.copy(), overhead: t.overhead.copy(), upstream: t.upstream.copy()}
	}
	return append([]series(nil), m.series...), times, m.collapsed
}

func (h histogram) copy() histogram {
	h.buckets = append([]uint64(nil), h.buckets...)
	return h
}

// AuxiliaryListener names a listener besides the data listener, in the order
// the metrics list them.
type AuxiliaryListener int

const (
	ListenerAdmin AuxiliaryListener = iota
	ListenerMetrics
	ListenerHealth
	ListenerRedirect
	auxiliaryListeners
)

var auxiliaryNames = [auxiliaryListeners]string{"admin", "metrics", "health", "redirect"}

// String is the listener's metric label value.
func (l AuxiliaryListener) String() string { return auxiliaryNames[l] }

// Redirected counts one redirect of the HTTP-to-HTTPS redirect listener.
func (o *Observations) Redirected() { o.redirects.Add(1) }

// HTTP2Error counts one HTTP/2 protocol error of the data listener; its type
// (Go's name for it) stays out of the metric, which counts them all.
func (o *Observations) HTTP2Error(string) { o.http2.Add(1) }

// ConnectionRefused counts one data connection closed at the cap.
func (o *Observations) ConnectionRefused() { o.refused.Add(1) }

// Refuser returns the function that counts one connection closed at the cap
// of listener.
func (o *Observations) Refuser(listener AuxiliaryListener) func() {
	count := &o.auxiliary[listener]
	return func() { count.Add(1) }
}

// AdminFailure is why the Admin API could not answer a request itself: a part
// of the gateway failed, not the request.
type AdminFailure int

const (
	FailStore   AdminFailure = iota // the database could not be read
	FailAudit                       // the security log did not confirm a record
	FailBusy                        // every password-hashing slot was in use
	FailLog                         // the security log files could not be read
	FailStreams                     // every live-view slot was in use
	adminFailures
)

var adminFailureNames = [adminFailures]string{"store", "audit", "busy", "log", "streams"}

// String is the failure's label value and refusal reason.
func (f AdminFailure) String() string { return adminFailureNames[f] }

// AdminFailed counts one Admin API failure.
func (o *Observations) AdminFailed(f AdminFailure) { o.admin[f].Add(1) }

// KeyReloadFailed counts one refused key reload.
func (o *Observations) KeyReloadFailed() { o.keyReloads.Add(1) }
