// The advice checks against fixed generations, traffic and security log files.

package monitor

import (
	"slices"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

func adviceGeneration(t *testing.T) *compile.Generation {
	t.Helper()
	g, err := compile.Compile(policy.Policy{
		SchemaVersion: policy.SchemaVersion, Profile: policy.ProfileCore,
		Upstreams: []policy.Upstream{{ID: "A", Dial: "127.0.0.1:9"}},
		APIs:      []policy.API{{ID: "a", Upstream: "A", ResponseHeaders: &policy.ResponseHeaders{HSTS: true}}},
		Operations: []policy.Operation{
			{ID: "open", API: "a", Method: "GET", Target: "/open", Access: "allow", Auth: "none"},
			{ID: "limited", API: "a", Method: "GET", Target: "/limited", Access: "allow", Auth: "none", Rate: &policy.RateRule{Algorithm: "sliding-window", Count: 5, WindowSeconds: 60, Key: "client_address"}},
			{ID: "orphan", API: "a", Method: "GET", Target: "/orphan", Access: "allow", Auth: "required", Rate: &policy.RateRule{Algorithm: "sliding-window", Count: 5, WindowSeconds: 60, Key: "subject"}},
			{ID: "read", API: "a", Method: "GET", Target: "/read", Access: "allow", Auth: "required"},
			{ID: "off", API: "a", Method: "GET", Target: "/off", Access: "deny", Auth: "none"},
		},
		Roles:   []policy.Role{{ID: "READER"}, {ID: "IDLE"}},
		Permits: []policy.Permit{{Role: "READER", Operation: "read"}},
	}, 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func ids(items []Finding) []string {
	out := []string{}
	for _, item := range items {
		out = append(out, item.ID+":"+item.Object)
	}
	return out
}

// The configuration warnings follow the fixed rules, in the fixed order, and
// a switched-off endpoint raises none. HSTS is reported once per API, and only
// when the gateway serves plain HTTP itself.
func TestConfigurationWarnings(t *testing.T) {
	g := adviceGeneration(t)
	got := ids(ConfigurationWarnings(g, true))
	want := []string{"W1:open", "W2:orphan", "W5:a", "W3:IDLE", "W4:read"}
	if !slices.Equal(got, want) {
		t.Errorf("plain HTTP: warnings %v, want %v", got, want)
	}
	got = ids(ConfigurationWarnings(g, false))
	want = []string{"W1:open", "W2:orphan", "W3:IDLE", "W4:read"}
	if !slices.Equal(got, want) {
		t.Errorf("host listener: warnings %v, want %v", got, want)
	}
}

func TestUnusedPermissions(t *testing.T) {
	g := adviceGeneration(t)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	few := PermitSnapshot{Used: map[[2]string]time.Time{}, Requests: 10, Since: now.Add(-2 * time.Hour)}
	if report := UnusedPermissions(g, few, now); report.Withheld == nil || len(report.Items) != 0 || report.WindowDays != PermitUseWindowDays {
		t.Errorf("too few requests: %+v", report)
	}
	recent := PermitSnapshot{Used: map[[2]string]time.Time{}, Requests: unusedMinRequests, Since: now.Add(-time.Minute)}
	if report := UnusedPermissions(g, recent, now); report.Withheld == nil {
		t.Errorf("too short a span: %+v", report)
	}
	enough := PermitSnapshot{Used: map[[2]string]time.Time{}, Requests: unusedMinRequests, Since: now.Add(-2 * time.Hour)}
	report := UnusedPermissions(g, enough, now)
	if report.Withheld != nil || !slices.Equal(ids(report.Items), []string{"U1:READER → read"}) || report.WindowDays != PermitUseWindowDays {
		t.Errorf("unused: %+v", report)
	}
	enough.Used[[2]string{"READER", "read"}] = now.Add(-31 * 24 * time.Hour)
	if report := UnusedPermissions(g, enough, now); len(report.Items) != 1 {
		t.Errorf("older than 30 days should still be unused: %+v", report)
	}
	enough.Used[[2]string{"READER", "read"}] = now.Add(-time.Hour)
	if report := UnusedPermissions(g, enough, now); len(report.Items) != 0 {
		t.Errorf("an admitted request in the last 30 days uses it: %+v", report)
	}
}

// A refusal spike needs enough refusals and a sharp rise over the period
// before; steady refusals are not a spike. A window that has dropped
// requests from inside the period before withholds the rule.
func TestRefusalSpike(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	burst := func(count int, decision string, from, span time.Duration) []audit.Event {
		var out []audit.Event
		for n := range count {
			recorded := "forwarded"
			if decision == "refused" {
				recorded = "reject"
			}
			out = append(out, audit.Event{Time: now.Add(-from + span*time.Duration(n)/time.Duration(count)), Decision: recorded, Status: 200})
		}
		return out
	}
	for _, tc := range []struct {
		name   string
		window int
		events []audit.Event
		spike  bool
	}{
		{"quiet before, a burst now", 1000, burst(25, "refused", 50*time.Second, 40*time.Second), true},
		{"below the minimum", 1000, burst(19, "refused", 50*time.Second, 40*time.Second), false},
		{"steady refusals", 1000, append(burst(300, "refused", 15*time.Minute, 14*time.Minute), burst(25, "refused", 50*time.Second, 40*time.Second)...), false},
		{"mostly allowed now", 1000, append(burst(25, "refused", 50*time.Second, 40*time.Second), burst(100, "allowed", 50*time.Second, 40*time.Second)...), false},
		{"rise over allowed traffic", 1000, append(append(burst(300, "allowed", 15*time.Minute, 14*time.Minute), burst(5, "refused", 10*time.Minute, time.Minute)...), burst(30, "refused", 50*time.Second, 40*time.Second)...), true},
		{"a burst after the window dropped part of the period before", 100, append(burst(300, "refused", 15*time.Minute, 14*time.Minute), burst(25, "refused", 50*time.Second, 40*time.Second)...), false},
		{"dropped requests older than the period before", 100, append(burst(300, "allowed", 30*time.Minute, time.Minute), burst(25, "refused", 50*time.Second, 40*time.Second)...), true},
	} {
		o := New(tc.window, 1)
		slices.SortFunc(tc.events, func(a, b audit.Event) int { return a.Time.Compare(b.Time) })
		for _, event := range tc.events {
			o.Record(event)
		}
		if got := RefusalSpike(o, now) != nil; got != tc.spike {
			t.Errorf("%s: spike %t, want %t", tc.name, got, tc.spike)
		}
	}
}
