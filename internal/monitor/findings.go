// The fixed advice checks: configuration warnings, unused permissions and
// refusal spikes, built from a generation and observed traffic.

package monitor

import (
	"cmp"
	"slices"
	"strconv"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// The fixed checks, rule set version "checks-0.8": static
// configuration warnings, unused permissions from observed traffic, and
// alerts. They advise only: nothing here blocks, changes or activates
// anything, and nothing runs on the request path. Each answer names the
// rule set version so findings can be traced to the rules that made them.
// The values below are the published rule set AdviceRules; changing one is a
// new rule set version, never a setting.
const (
	AdviceRules = "checks-0.8"

	// Alert A5 warns before a TLS certificate expires: medium below 14 days,
	// critical below 3 days or already expired.
	CertWarnDays     = 14 * 24 * time.Hour
	CertCriticalDays = 3 * 24 * time.Hour

	// The security log also raises an alert when, at the active file's recent
	// write rate, its remaining budget lasts less than FillingTime (medium) or
	// NearlyFullTime (critical). The rate is read over the file's last
	// RateMinBytes and counts once the file holds that much, so a few early
	// records cannot predict a fill and a slow start does not dilute it.
	// An hour of warning leaves time to move earlier files before the log fills.
	// A quarter hour is the last warning before it fills and requests are refused.
	FillingTime    = time.Hour
	NearlyFullTime = 15 * time.Minute
	RateMinBytes   = 1 << 20

	// Unused permissions are withheld until the request records read from
	// the security log span this long and number this many.
	// An hour of records keeps a quiet spell from making a permission look unused.
	// Five hundred requests keep too little traffic from doing the same.
	unusedMinSpan     = 60 * time.Minute
	unusedMinRequests = 500

	// A refusal spike: at least spikeMinRefusals in the last spikeWindow and
	// a refused share at least spikeFactor times that of the spikeBaseline
	// before it, or at least spikeLowTrafficShare when that period had fewer
	// than spikeMinRefusals requests.
	// The window is the minute the alert names.
	// The quarter hour before gives the refusal share to compare with.
	// Below twenty refusals in the minute nothing is raised, so a handful stays quiet.
	// Three times the baseline share marks a jump rather than ordinary drift.
	// With a thin baseline, half the minute refused raises the finding.
	spikeWindow          = time.Minute
	spikeBaseline        = 15 * time.Minute
	spikeMinRefusals     = 20
	spikeFactor          = 3.0
	spikeLowTrafficShare = 0.5

	// NearlyFull is the share of a store that raises an alert; Filling, the
	// share of the security log budget that raises an earlier one.
	// Nine tenths is the last warning before the security log or the counters fill.
	// Seven tenths of the security log leaves time to move earlier files away.
	NearlyFull = 0.9
	Filling    = 0.7
)

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Object   string `json:"object"`
	Message  string `json:"message"`
}

var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// SortFindings gives the fixed order: severity, rule, object.
func SortFindings(items []Finding) {
	slices.SortFunc(items, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(severityOrder[a.Severity], severityOrder[b.Severity]), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Object, b.Object))
	})
}

// ConfigurationWarnings reads the compiled generation and, for HSTS, whether
// the gateway serves the data plane itself over plain HTTP (plain). A host
// program's listener may use TLS, which the gateway cannot see, so plain is
// false there and HSTS raises nothing.
func ConfigurationWarnings(g *compile.Generation, plain bool) []Finding {
	items := []Finding{}
	usedRoles := map[string]bool{}
	hstsAPIs := map[string]bool{}
	for _, r := range g.Rules() {
		for _, role := range r.Roles() {
			usedRoles[role] = true
		}
		if plain && r.Response() != nil && r.Response().HSTS() && !hstsAPIs[r.API()] {
			hstsAPIs[r.API()] = true
			items = append(items, Finding{"W5", "medium", r.API(), "The API tells browsers to use HTTPS only (HSTS), but the gateway receives plain HTTP, so the header is never sent. Set HSTS where TLS ends, such as on the proxy in front of the gateway."})
		}
		if !r.Permitted() {
			continue
		}
		switch {
		case r.Public() && r.Rate() == nil:
			items = append(items, Finding{"W1", "high", r.Operation(), "A public endpoint has no rate limit, so anyone can call it without limit."})
		case !r.Public() && len(r.Roles()) == 0:
			items = append(items, Finding{"W2", "medium", r.Operation(), "The endpoint is switched on and needs sign-in, but no role has permission, so no one can call it."})
		case !r.Public() && r.Rate() == nil:
			items = append(items, Finding{"W4", "low", r.Operation(), "A signed-in endpoint has no rate limit."})
		}
	}
	for _, role := range g.Roles() {
		if !usedRoles[role] {
			items = append(items, Finding{"W3", "low", role, "The role has no permissions."})
		}
	}
	SortFindings(items)
	return items
}

// HostTransport is the informational finding W6 of a gateway whose data
// plane a host program serves: the host owns TLS, so the gateway cannot
// tell whether requests arrive over HTTPS.
func HostTransport() Finding {
	return Finding{"W6", "info", "data_plane", "The host program serves the data plane, so the gateway cannot confirm that requests arrive over HTTPS. Make sure the host program uses TLS."}
}

type UnusedReport struct {
	Requests   int       `json:"requests"`
	Since      *string   `json:"since"`
	WindowDays int       `json:"window_days"`
	Withheld   *string   `json:"withheld"`
	Items      []Finding `json:"items"`
	MinMinute  int       `json:"min_minutes"`
	MinCount   int       `json:"min_requests"`
}

// UnusedPermissions lists permits with no admitted request in the last
// PermitUseWindowDays (or since tracking began, when shorter), once tracking
// covers at least unusedMinSpan and unusedMinRequests admitted requests.
func UnusedPermissions(g *compile.Generation, snap PermitSnapshot, now time.Time) UnusedReport {
	report := UnusedReport{
		Requests: snap.Requests, WindowDays: PermitUseWindowDays, Items: []Finding{},
		MinMinute: int(unusedMinSpan / time.Minute), MinCount: unusedMinRequests,
	}
	if !snap.Since.IsZero() {
		since := snap.Since.UTC().Format(time.RFC3339)
		report.Since = &since
	}
	if snap.Requests < unusedMinRequests || snap.Since.IsZero() || now.Sub(snap.Since) < unusedMinSpan {
		reason := "Not enough traffic has been recorded yet."
		report.Withheld = &reason
		return report
	}
	cutoff := now.Add(-permitUseWindow)
	for _, r := range g.Rules() {
		if r.Public() || !r.Permitted() {
			continue
		}
		for _, role := range r.Roles() {
			last, ok := snap.Used[[2]string{role, r.Operation()}]
			if !ok || last.Before(cutoff) {
				report.Items = append(report.Items, Finding{"U1", "low", role + " → " + r.Operation(), "No admitted request in the last 30 days used this permission. Review whether the role still needs it."})
			}
		}
	}
	SortFindings(report.Items)
	return report
}

// RefusalSpike applies the spike rule to the retained observations. It
// counts without copying the window, and is withheld (nil) when the window
// has dropped requests from inside the baseline period, whose share would
// then be read from part of it. A request stamped after now (a clock step)
// counts in the last minute.
func RefusalSpike(o *Observations, now time.Time) *Finding {
	from := now.Add(-spikeWindow - spikeBaseline)
	if oldest, dropped := o.RetainedSince(); dropped && oldest.After(from) {
		return nil
	}
	var recent, recentRefused, before, beforeRefused int
	o.Walk(from, func(event *Entry) bool {
		age := now.Sub(event.Time)
		refused := event.Decision == Refused
		switch {
		case age <= spikeWindow:
			recent++
			if refused {
				recentRefused++
			}
		case age <= spikeWindow+spikeBaseline:
			before++
			if refused {
				beforeRefused++
			}
		}
		return true
	})
	if recentRefused < spikeMinRefusals {
		return nil
	}
	share := float64(recentRefused) / float64(recent)
	spiking := share >= spikeLowTrafficShare
	if before >= spikeMinRefusals {
		spiking = share >= spikeFactor*float64(beforeRefused)/float64(before)
	}
	if !spiking {
		return nil
	}
	return &Finding{"A1", "high", "refusals", strconv.Itoa(recentRefused) + " of " + strconv.Itoa(recent) + " requests were refused in the last minute, far more than before. Look up the refused requests to see who is sending them."}
}
