// Admin API event list and event stream handlers.

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

func knownQuery(query url.Values, names ...string) bool {
	for name, values := range query {
		if len(values) != 1 || !slices.Contains(names, name) {
			return false
		}
	}
	return true
}

func (c *Controller) handleEvents(w http.ResponseWriter, r *http.Request, who caller) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	limit := 20
	if text := query.Get("limit"); text != "" {
		limit, err = strconv.Atoi(text)
		if strconv.Itoa(limit) != text {
			err = fmt.Errorf("invalid limit")
		}
	}
	ref, subject, operation, decision := query.Get("ref"), query.Get("subject"), query.Get("operation"), query.Get("decision")
	validDecision := decision == "" || decision == "allowed" || decision == "refused"
	if err != nil || !knownQuery(query, "ref", "subject", "operation", "decision", "limit", "after") || limit < 1 || limit > 100 || !validDecision {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	after := uint64(0)
	if text := query.Get("after"); text != "" {
		after, err = strconv.ParseUint(text, 10, 64)
		if err != nil || after == 0 || strconv.FormatUint(after, 10) != text {
			adminError(w, http.StatusBadRequest, "bad_request", "")
			return
		}
	}
	// One match beyond the page says whether a next page exists.
	matches := c.observations.Recent(func(event *monitor.Observed) bool {
		return (after == 0 || event.Sequence() < after) &&
			(ref == "" || event.RequestID == ref) &&
			(subject == "" || (event.Subject != nil && *event.Subject == subject)) &&
			(operation == "" || (event.Operation != nil && *event.Operation == operation)) &&
			(decision == "" || event.Decision == decision)
	}, limit+1)
	items := []monitor.RequestView{}
	next := ""
	for i, event := range matches {
		if i == limit {
			next = strconv.FormatUint(matches[limit-1].Sequence(), 10)
			break
		}
		items = append(items, event.RequestView)
	}
	pipeline.WriteJSON(w, http.StatusOK, list{Items: items, Next: next})
}

func (c *Controller) handleEventStream(w http.ResponseWriter, r *http.Request, who caller) {
	if r.Header.Get("Accept") != "text/event-stream" || r.URL.RawQuery != "" {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	viewer := c.observations.Subscribe()
	if viewer == nil {
		adminError(w, http.StatusServiceUnavailable, "stream_limit", "")
		return
	}
	defer c.observations.Unsubscribe(viewer)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	controller := http.NewResponseController(w)
	write := func(data string) bool {
		if controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
			return false
		}
		if _, err := fmt.Fprint(w, data); err != nil {
			return false
		}
		if controller.Flush() != nil {
			return false
		}
		return controller.SetWriteDeadline(time.Time{}) == nil
	}
	if !write(": connected\n\n") {
		return
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	expiry := time.NewTimer(time.Until(who.session.Expires))
	defer expiry.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-c.observations.Closing():
			return
		case <-who.session.Closed():
			return
		case <-expiry.C:
			return
		case <-heartbeat.C:
			if !c.sessions.Active(who.token, time.Now()) {
				return
			}
			if !write(": heartbeat\n\n") {
				return
			}
		case event := <-viewer.Feed():
			if !c.sessions.Active(who.token, time.Now()) {
				return
			}
			if count := c.observations.TakeDropped(viewer); count > 0 {
				if !write(fmt.Sprintf("event: dropped\ndata: {\"count\":%d}\n\n", count)) {
					return
				}
			}
			data, _ := json.Marshal(event.RequestView)
			if !write("event: request\ndata: " + string(data) + "\n\n") {
				return
			}
		}
	}
}
