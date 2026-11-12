// Alert A3 by the share of the security log budget in use and by the time
// the rest of the budget lasts at the active file's write rate (checks-0.5).

package admin

import (
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
)

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
		alert := logFilling(used, budget, pace(tc.active, at(tc.left), now), tc.evicts)
		if severity := severityOf(alert); severity != tc.severity {
			t.Errorf("%s: severity %q, want %q", tc.name, severity, tc.severity)
		}
		if alert != nil && !strings.Contains(alert.Message, "full in "+tc.minutes+".") {
			t.Errorf("%s: message %q does not state %q", tc.name, alert.Message, tc.minutes)
		}
	}
}
