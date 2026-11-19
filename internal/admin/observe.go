// Admin API event list and event stream handlers.

package admin

import (
	"bytes"
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

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, who caller) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	// A default page of 20 keeps one read's copy from the live ring and the answer small.
	limit := 20
	if text := query.Get("limit"); text != "" {
		limit, err = strconv.Atoi(text)
		if strconv.Itoa(limit) != text {
			err = fmt.Errorf("invalid limit")
		}
	}
	ref, subject, operation, decision := query.Get("ref"), query.Get("subject"), query.Get("operation"), query.Get("decision")
	validDecision := decision == "" || slices.Contains(monitor.Decisions, decision)
	// A page above 100 events is refused, so one read copies only a bounded part of the ring.
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
	matches := s.observations.Recent(func(event *monitor.Entry) bool {
		return (after == 0 || event.Sequence() < after) &&
			(ref == "" || event.RequestID == ref) &&
			(subject == "" || event.Subject == subject) &&
			(operation == "" || event.Operation == operation) &&
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

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request, who caller) {
	if r.Header.Get("Accept") != "text/event-stream" || r.URL.RawQuery != "" {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	viewer := s.observations.Subscribe()
	if viewer == nil {
		s.fail(w, r, &who, "stream_limit", monitor.FailStreams, nil)
		return
	}
	defer s.observations.Unsubscribe(viewer)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	controller := http.NewResponseController(w)
	write := func(data []byte) bool {
		// Each frame has a 5 s write deadline, so a stalled viewer ends the stream instead of holding it.
		if controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
			return false
		}
		if _, err := w.Write(data); err != nil {
			return false
		}
		if controller.Flush() != nil {
			return false
		}
		return controller.SetWriteDeadline(time.Time{}) == nil
	}
	if !write([]byte(": connected\n\n")) {
		return
	}
	// An idle stream is kept alive every 15 s, and each beat re-checks the session.
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	expiry := time.NewTimer(time.Until(who.session.Expires))
	defer expiry.Stop()
	// One buffer and encoder serve every frame of the stream.
	var frame bytes.Buffer
	encoder := json.NewEncoder(&frame)
	checked := time.Now()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.observations.Closing():
			return
		case <-who.session.Closed():
			return
		case <-expiry.C:
			return
		case <-heartbeat.C:
			if !s.sessions.Active(who.token, time.Now()) {
				return
			}
			if !write([]byte(": heartbeat\n\n")) {
				return
			}
		case event := <-viewer.Feed():
			// A revoked session ends the stream through Closed and an expired
			// one through the timer; idle expiry is checked at most once a
			// second, not for every event, as the check takes the session lock.
			if now := time.Now(); now.Sub(checked) >= time.Second {
				if !s.sessions.Active(who.token, now) {
					return
				}
				checked = now
			}
			frame.Reset()
			if count := s.observations.TakeDropped(viewer); count > 0 {
				fmt.Fprintf(&frame, "event: dropped\ndata: {\"count\":%d}\n\n", count)
			}
			frame.WriteString("event: request\ndata: ")
			// Encode ends the value with a line feed, which ends the data line.
			if encoder.Encode(event.View()) != nil {
				return
			}
			frame.WriteString("\n")
			if !write(frame.Bytes()) {
				return
			}
		}
	}
}
