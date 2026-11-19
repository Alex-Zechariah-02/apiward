// Benchmarks of the Admin API reads the Dashboard polls: traffic, status,
// policy and limits, each over a controller opened on a seeded database.

package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// benchRead runs handler for path once per iteration and checks the answer.
func benchRead(b *testing.B, handler adminHandler, path string) {
	b.Helper()
	b.ReportAllocs()
	for b.Loop() {
		reply := httptest.NewRecorder()
		handler(reply, httptest.NewRequest(http.MethodGet, path, nil), caller{})
		if reply.Code != http.StatusOK {
			b.Fatalf("%s: %d %s", path, reply.Code, reply.Body)
		}
	}
}

// BenchmarkTraffic reads the one-minute traffic summary of a full window
// recorded at 100 requests a second.
func BenchmarkTraffic(b *testing.B) {
	s := testServer(openController(b))
	now := time.Now()
	for i := range s.observations.Window() {
		s.observations.Record(audit.Event{RequestID: fmt.Sprint(i), Time: now.Add(-time.Duration(s.observations.Window()-i) * 10 * time.Millisecond),
			Method: "GET", Path: "/a", Operation: "a.read", API: "a", Decision: "forwarded", Stage: "FORWARD", Status: 200, DurationMS: float64(i % 7)})
	}
	benchRead(b, s.handleTraffic, "/admin/traffic?window=60")
}

func BenchmarkStatus(b *testing.B) {
	s := testServer(openController(b))
	benchRead(b, s.handleStatus, "/admin/status")
}

func BenchmarkPolicy(b *testing.B) {
	s := testServer(openController(b))
	benchRead(b, s.handlePolicy, "/admin/policy")
}

func BenchmarkLimits(b *testing.B) {
	s := testServer(openController(b))
	benchRead(b, s.handleLimits, "/admin/limits")
}
