// The live-traffic stream stops as soon as its session is revoked, even when
// request events are already queued on its feed at the same instant.

package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

type streamFlushRecorder struct {
	*httptest.ResponseRecorder
	onFirstFlush func()
	flushed      bool
}

func (r *streamFlushRecorder) SetWriteDeadline(time.Time) error { return nil }

func (r *streamFlushRecorder) Flush() {
	r.ResponseRecorder.Flush()
	if !r.flushed {
		r.flushed = true
		if r.onFirstFlush != nil {
			r.onFirstFlush()
		}
	}
}

func TestEventStreamStopsImmediatelyOnRevoke(t *testing.T) {
	c := openController(t)
	s := testServer(c)

	for i := range 25 {
		token, sess, err := s.sessions.Create("ops", 1, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		rec := &streamFlushRecorder{
			ResponseRecorder: httptest.NewRecorder(),
			onFirstFlush: func() {
				// Make both the session-closed channel and the event feed ready
				// before handleEventStream enters its select loop.
				s.sessions.Revoke(token)
				for range 8 {
					s.observations.Record(audit.Event{
						Kind:      "request.admitted",
						RequestID: "after-logout",
						Method:    http.MethodGet,
						Path:      "/a/after-logout",
						Decision:  "allow",
					})
				}
			},
		}
		req := httptest.NewRequest(http.MethodGet, "/admin/events/stream", nil)
		req.Header.Set("Accept", "text/event-stream")
		s.handleEventStream(rec, req, caller{session: sess, token: token})
		if !strings.Contains(rec.Body.String(), ": connected") {
			t.Fatalf("trial %d: stream never connected:\n%s", i, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "event: request") {
			t.Fatalf("trial %d: stream sent request event after session revoke:\n%s", i, rec.Body.String())
		}
	}
}
