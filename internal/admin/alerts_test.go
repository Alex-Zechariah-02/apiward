// Alert A3 by the share of the security log budget in use (checks-0.4).

package admin

import "testing"

func TestLogFillingThresholds(t *testing.T) {
	cases := []struct {
		used, budget int64
		severity     string
	}{
		{69, 100, ""}, {70, 100, "medium"}, {89, 100, "medium"}, {90, 100, "critical"}, {120, 100, "critical"}, {0, 0, ""},
	}
	for _, tc := range cases {
		alert := logFilling(tc.used, tc.budget)
		severity := ""
		if alert != nil {
			severity = alert.Severity
		}
		if severity != tc.severity {
			t.Errorf("%d of %d: severity %q, want %q", tc.used, tc.budget, severity, tc.severity)
		}
	}
}
