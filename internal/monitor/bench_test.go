// Benchmarks of the monitor's request-path and control-plane costs: recording
// a request, reading the window, scraping metrics and scanning the security
// log. Each compares one workload before and after a change; none is a test.

package monitor

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// benchEvent is a forwarded request of a signed-in account with two roles.
func benchEvent(i int) audit.Event {
	e := audit.Event{RequestID: fmt.Sprintf("%032x", i), Time: time.Now(), Method: "GET", Path: "/orders/1001/items",
		Operation: "orders.read", API: "orders", Subject: "user-1", Roles: []string{"reader", "support"},
		ClientAddress: "192.0.2.10", Decision: "forwarded", Stage: "FORWARD", Status: 200, Generation: "g-1", DurationMS: 1.2, UpstreamMS: 0.8}
	e.Stages[audit.StageCanonical] = audit.StagePass
	return e
}

// BenchmarkRecord is the per-request cost of recording with no live view.
func BenchmarkRecord(b *testing.B) {
	o := New(policy.DefaultWindow, policy.DefaultAPIs)
	event := benchEvent(1)
	b.ReportAllocs()
	for b.Loop() {
		o.Record(event)
	}
}

// BenchmarkRecordParallel records from every core at once.
func BenchmarkRecordParallel(b *testing.B) {
	o := New(policy.DefaultWindow, policy.DefaultAPIs)
	event := benchEvent(1)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			o.Record(event)
		}
	})
}

// BenchmarkSpike evaluates the refusal-spike alert over a full ring.
func BenchmarkSpike(b *testing.B) {
	o := New(policy.DefaultWindow, policy.DefaultAPIs)
	fillObservations(o, policy.DefaultWindow, time.Now())
	b.ReportAllocs()
	for b.Loop() {
		benchSpike(o, time.Now())
	}
}

// BenchmarkScrape serves /metrics with the series cap filled.
func BenchmarkScrape(b *testing.B) {
	o := New(policy.DefaultWindow, policy.DefaultAPIs)
	for i := range 4096 {
		event := benchEvent(i)
		event.Operation = fmt.Sprintf("orders.op%d", i)
		o.Record(event)
	}
	handler := Metrics(o, func() []Gauge { return nil })
	b.ReportAllocs()
	for b.Loop() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/metrics", nil))
	}
}

// benchLog writes an audit file of about size bytes of request records.
func benchLog(b *testing.B, size int) string {
	b.Helper()
	var text strings.Builder
	for i := 0; text.Len() < size; i++ {
		fmt.Fprintf(&text, `{"schema":8,"event_id":"e%d","time":%q,"seq":%d,"kind":"request.forwarded","request_id":"r%d","stage":"FORWARD","decision":"forwarded","status":200,"method":"GET","path":"/orders/%d","operation":"orders.read","api":"orders","subject":"user-%d","roles":["reader"],"client_address":"192.0.2.10","duration_ms":1.5,"generation":"g-1","pad":"%s"}`+"\n",
			i, time.Now().Add(-2*time.Hour).Add(time.Duration(i)*time.Millisecond).UTC().Format(time.RFC3339Nano), i, i, i, i%50, strings.Repeat("x", 200))
	}
	path := filepath.Join(b.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte(text.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	return path
}

// BenchmarkPermitUse is a repeated advice read of an unchanged 32 MiB active file.
func BenchmarkPermitUse(b *testing.B) {
	path := benchLog(b, 32<<20)
	var c Summaries
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.PermitUse(context.Background(), filepath.Dir(path), []string{filepath.Base(path)}, ExportScan); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSearchExport scans 32 MiB for a record that is not there.
func BenchmarkSearchExport(b *testing.B) {
	path := benchLog(b, 32<<20)
	query, _ := ParseQuery(map[string][]string{"ref": {"absent"}})
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Search(context.Background(), filepath.Dir(path), []string{filepath.Base(path)}, nil, query, ExportRows, ExportScan); err != nil {
			b.Fatal(err)
		}
	}
}

func benchSpike(o *Observations, now time.Time) *Finding { return RefusalSpike(o, now) }
