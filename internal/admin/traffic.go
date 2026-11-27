// Admin API traffic summary.

package admin

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

const (
	windowMinute = 60
	windowFive   = 300
	windowHour   = 3600
)

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request, who caller) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	window := windowMinute
	if text := query.Get("window"); text != "" {
		window, err = strconv.Atoi(text)
		if strconv.Itoa(window) != text {
			err = fmt.Errorf("invalid window")
		}
	}
	// Only these spans are accepted; an answer reads the current and previous window.
	if err != nil || !knownQuery(query, "window") || (window != windowMinute && window != windowFive && window != windowHour) {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	type reason struct {
		Code  string `json:"code"`
		Count int    `json:"count"`
	}
	type second struct {
		At      time.Time `json:"at"`
		Allowed int       `json:"allowed"`
		Refused int       `json:"refused"`
	}
	type refusedBy struct {
		Kind       string `json:"kind"`
		ID         string `json:"id"`
		Refused    int    `json:"refused"`
		LatestCode string `json:"latest_code"`
	}
	type totals struct {
		Total   int `json:"total"`
		Allowed int `json:"allowed"`
		Refused int `json:"refused"`
	}
	type interval struct {
		At        time.Time `json:"at"`
		Count     int       `json:"count"`
		P50       float64   `json:"p50_ms"`
		P95       float64   `json:"p95_ms"`
		durations []float64
	}
	now := time.Now().UTC()
	span := time.Duration(window) * time.Second
	start := now.Add(-span)
	previousStart := start.Add(-span)
	// Latency intervals match the chart's: window/60 seconds, on whole
	// multiples of their length on the clock.
	step := int64(window / 60)
	apis := map[string]*monitor.TrafficGroup{}
	operations := map[string]*monitor.TrafficGroup{}
	refusers := map[string]*refusedBy{}
	reasons := map[string]int{}
	seconds := map[int64]*second{}
	intervals := map[int64]*interval{}
	current, previous := totals{}, totals{}
	// The ring is newest first, so the latest refusal code of each account or
	// address is the first one seen. The walk ends soon after previousStart.
	s.observations.Walk(previousStart, func(event *monitor.Entry) bool {
		if event.Time.Before(previousStart) || event.Time.After(now) {
			return true
		}
		allowed := event.Allowed()
		if event.Time.Before(start) {
			previous.Total++
			if allowed {
				previous.Allowed++
			} else {
				previous.Refused++
			}
			return true
		}
		current.Total++
		api := cmp.Or(event.API, "unknown")
		if apis[api] == nil {
			apis[api] = &monitor.TrafficGroup{API: api}
		}
		apis[api].Add(event)
		if event.Operation != "" {
			if operations[event.Operation] == nil {
				operations[event.Operation] = &monitor.TrafficGroup{API: api, Operation: event.Operation}
			}
			operations[event.Operation].Add(event)
		}
		at := event.Time.Unix()
		if seconds[at] == nil {
			seconds[at] = &second{At: time.Unix(at, 0).UTC()}
		}
		bucket := at - at%step
		if intervals[bucket] == nil {
			intervals[bucket] = &interval{At: time.Unix(bucket, 0).UTC()}
		}
		intervals[bucket].Count++
		intervals[bucket].durations = append(intervals[bucket].durations, event.DurationMS)
		if allowed {
			current.Allowed++
			seconds[at].Allowed++
			return true
		}
		current.Refused++
		seconds[at].Refused++
		if event.Code != "" {
			reasons[event.Code]++
		}
		kind, id := "address", event.ClientAddress
		if event.Subject != "" {
			kind, id = "account", event.Subject
		}
		key := kind + " " + id
		if refusers[key] == nil {
			refusers[key] = &refusedBy{Kind: kind, ID: id, LatestCode: event.Code}
		}
		refusers[key].Refused++
		return true
	})
	byAPI := []monitor.TrafficGroup{}
	for _, name := range slices.Sorted(maps.Keys(apis)) {
		byAPI = append(byAPI, apis[name].Settle())
	}
	byOperation := []monitor.TrafficGroup{}
	for _, group := range operations {
		byOperation = append(byOperation, group.Settle())
	}
	byOperation = monitor.TrafficTop(byOperation, func(g monitor.TrafficGroup) int { return g.Total }, func(g monitor.TrafficGroup) string { return g.Operation }, monitor.TopLimit)
	topRefused := []refusedBy{}
	for _, entry := range refusers {
		topRefused = append(topRefused, *entry)
	}
	topRefused = monitor.TrafficTop(topRefused, func(e refusedBy) int { return e.Refused }, func(e refusedBy) string { return e.Kind + " " + e.ID }, monitor.TopLimit)
	refusalReasons := []reason{}
	for _, code := range slices.Sorted(maps.Keys(reasons)) {
		refusalReasons = append(refusalReasons, reason{code, reasons[code]})
	}
	perSecond := []second{}
	for _, at := range slices.Sorted(maps.Keys(seconds)) {
		perSecond = append(perSecond, *seconds[at])
	}
	latency := []interval{}
	for _, at := range slices.Sorted(maps.Keys(intervals)) {
		entry := intervals[at]
		entry.P50, entry.P95 = monitor.Percentiles(entry.durations)
		latency = append(latency, *entry)
	}
	// A comparison needs the whole previous window: when the ring has dropped
	// requests from inside it, the count would be too low, so none is given.
	// The current window is answered from what the ring holds, and says from
	// when it is complete, so a chart can show the seconds before as unknown.
	var earlier *totals
	oldest, dropped := s.observations.RetainedSince()
	if !dropped || !oldest.After(previousStart) {
		earlier = &previous
	}
	covers, complete := start, !dropped || !oldest.After(start)
	if !complete {
		covers = oldest.UTC()
	}
	pipeline.WriteJSON(w, http.StatusOK, struct {
		Window      int                    `json:"window_seconds"`
		Total       int                    `json:"total"`
		Allowed     int                    `json:"allowed"`
		Refused     int                    `json:"refused"`
		ByAPI       []monitor.TrafficGroup `json:"by_api"`
		Reasons     []reason               `json:"refusal_reasons"`
		Seconds     []second               `json:"per_second"`
		ByOperation []monitor.TrafficGroup `json:"by_operation"`
		TopRefused  []refusedBy            `json:"top_refused"`
		Previous    *totals                `json:"previous"`
		Latency     []interval             `json:"latency"`
		CoversFrom  time.Time              `json:"covers_from"`
		Complete    bool                   `json:"complete"`
	}{window, current.Total, current.Allowed, current.Refused, byAPI, refusalReasons, perSecond, byOperation, topRefused, earlier, latency, covers, complete})
}
