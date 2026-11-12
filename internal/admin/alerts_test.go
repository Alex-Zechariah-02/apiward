// Alert A3 by the share of the security log budget in use and by the time
// the rest of the budget lasts at the active file's recent write rate
// (checks-0.6).

package admin

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

// TestLogFillingRecentRate writes a slow first hour and a fast last four
// minutes, then a zero tail as Linux preallocation leaves: the rate read over
// the last 1 MiB predicts from the fast span; the rate since the file's first
// record would predict hours.
func TestLogFillingRecentRate(t *testing.T) {
	now := time.Now()
	const size, slow, fast = 1024, 2048, 4096
	interval := 4 * time.Minute / fast
	var file bytes.Buffer
	record := func(i int, at time.Time) {
		line := fmt.Sprintf(`{"event_id":"e%d","time":%q,"pad":"`, i, at.UTC().Format(time.RFC3339Nano))
		fmt.Fprintf(&file, "%s%s\"}\n", line, strings.Repeat("x", size-len(line)-3))
	}
	for i := range slow {
		record(i, now.Add(-time.Hour-4*time.Minute+time.Duration(i)*time.Hour/slow))
	}
	for i := range fast {
		record(slow+i, now.Add(-time.Duration(fast-i)*interval))
	}
	active := int64(file.Len())
	file.Write(make([]byte, 64<<10))
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, file.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	recent, first, err := monitor.RecentRecord(path, monitor.RateMinBytes)
	if err != nil || recent > monitor.RateMinBytes || recent < monitor.RateMinBytes-size {
		t.Fatalf("recent span %d bytes, err %v", recent, err)
	}
	// The remaining budget lasts 10 minutes at the fast span's rate.
	rate := float64(size) / interval.Seconds()
	const used = 10 << 20
	budget := used + int64(rate*600)
	alert := logFilling(used, budget, pace(active, recent, first, now), false)
	if severityOf(alert) != "critical" || !strings.Contains(alert.Message, "full in about 10 minutes.") {
		t.Fatalf("alert %+v, want critical in about 10 minutes", alert)
	}
	// A file that rotated in after the size was read holds less than the
	// span: no rate, so one fresh record cannot predict a fill.
	fresh := filepath.Join(t.TempDir(), "fresh.log")
	if err := os.WriteFile(fresh, file.Bytes()[active-size:], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, first, err := monitor.RecentRecord(fresh, monitor.RateMinBytes); err != nil || !first.IsZero() {
		t.Fatalf("fresh file: time %v, err %v; want none", first, err)
	}
}

func severityOf(alert *monitor.Finding) string {
	if alert == nil {
		return ""
	}
	return alert.Severity
}

func TestLogFillingThresholds(t *testing.T) {
	cases := []struct {
		used, budget int64
		severity     string
	}{
		{69, 100, ""}, {70, 100, "medium"}, {89, 100, "medium"}, {90, 100, "critical"}, {120, 100, "critical"}, {0, 0, ""},
	}
	for _, tc := range cases {
		if severity := severityOf(logFilling(tc.used, tc.budget, 0, false)); severity != tc.severity {
			t.Errorf("%d of %d: severity %q, want %q", tc.used, tc.budget, severity, tc.severity)
		}
	}
}

func TestLogFillingTime(t *testing.T) {
	now := time.Now()
	// 10 % of a 100 MiB budget used; the active file wrote 4 MiB.
	const budget, used, active = 100 << 20, 10 << 20, 4 << 20
	at := func(left time.Duration) time.Time {
		// The start that makes the remaining 90 MiB last left.
		elapsed := time.Duration(float64(left) * active / float64(budget-used))
		return now.Add(-elapsed)
	}
	cases := []struct {
		name     string
		active   int64
		left     time.Duration
		evicts   bool
		severity string
		minutes  string
	}{
		{"two hours left", active, 2 * time.Hour, false, "", ""},
		{"medium under an hour", active, 50 * time.Minute, false, "medium", "about 50 minutes"},
		{"critical under fifteen minutes", active, 10 * time.Minute, false, "critical", "about 10 minutes"},
		{"below 1 MiB not raised", monitor.RateMinBytes - 1, time.Minute, false, "", ""},
		{"evict_oldest not raised", active, time.Minute, true, "", ""},
	}
	for _, tc := range cases {
		alert := logFilling(used, budget, pace(tc.active, active, at(tc.left), now), tc.evicts)
		if severity := severityOf(alert); severity != tc.severity {
			t.Errorf("%s: severity %q, want %q", tc.name, severity, tc.severity)
		}
		if alert != nil && !strings.Contains(alert.Message, "full in "+tc.minutes+".") {
			t.Errorf("%s: message %q does not state %q", tc.name, alert.Message, tc.minutes)
		}
	}
}
