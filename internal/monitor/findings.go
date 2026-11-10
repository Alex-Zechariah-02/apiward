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

// The fixed checks, rule set version "checks-0.4": static
// configuration warnings, unused permissions from observed traffic, and
// alerts. They advise only: nothing here blocks, changes or activates
// anything, and nothing runs on the request path. Each answer names the
// rule set version so findings can be traced to the rules that made them.
const (
	AdviceRules = "checks-0.4"

	// Unused permissions are withheld until the request records read from
	// the security log span this long and number this many.
	unusedMinSpan     = 60 * time.Minute
	unusedMinRequests = 500

	// A refusal spike: at least spikeMinRefusals in the last spikeWindow and
	// a refused share at least spikeFactor times that of the spikeBaseline
	// before it, or at least spikeLowTrafficShare when that period had fewer
	// than spikeMinRefusals requests.
	spikeWindow          = time.Minute
	spikeBaseline        = 15 * time.Minute
	spikeMinRefusals     = 20
	spikeFactor          = 3.0
	spikeLowTrafficShare = 0.5

	// NearlyFull is the share of a store that raises an alert; Filling, the
	// share of the security log budget that raises an earlier one.
	NearlyFull = 0.9
	Filling    = 0.7
)

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Object   string `json:"object"`
	Message  string `json:"message"`
}

var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

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

type UnusedReport struct {
	Requests      int       `json:"requests"`
	Since         *string   `json:"since"`
	Complete      bool      `json:"complete"`
	FilesSearched []string  `json:"files_searched"`
	FilesMissing  []string  `json:"files_missing"`
	Withheld      *string   `json:"withheld"`
	Items         []Finding `json:"items"`
	MinMinute     int       `json:"min_minutes"`
	MinCount      int       `json:"min_requests"`
}

// UnusedPermissions lists permits no allowed request in the security log
// used, once the records read cover enough time and requests. missing names
// log files moved away, which were not read.
func UnusedPermissions(g *compile.Generation, use LogUse, missing []string, now time.Time) UnusedReport {
	report := UnusedReport{
		Requests: use.requests, Complete: use.complete, FilesSearched: use.Searched, FilesMissing: missing, Items: []Finding{},
		MinMinute: int(unusedMinSpan / time.Minute), MinCount: unusedMinRequests,
	}
	if report.FilesSearched == nil {
		report.FilesSearched = []string{}
	}
	if report.FilesMissing == nil {
		report.FilesMissing = []string{}
	}
	if use.requests > 0 {
		since := use.oldest.UTC().Format(time.RFC3339)
		report.Since = &since
	}
	if use.requests < unusedMinRequests || now.Sub(use.oldest) < unusedMinSpan {
		reason := "Not enough traffic has been recorded yet."
		report.Withheld = &reason
		return report
	}
	for _, r := range g.Rules() {
		if r.Public() || !r.Permitted() {
			continue
		}
		for _, role := range r.Roles() {
			if !use.used[[2]string{role, r.Operation()}] {
				report.Items = append(report.Items, Finding{"U1", "low", role + " → " + r.Operation(), "No allowed request in the security log used this permission. Review whether the role still needs it."})
			}
		}
	}
	SortFindings(report.Items)
	return report
}

// RefusalSpike applies the spike rule to the retained observations.
func RefusalSpike(events []Observed, now time.Time) *Finding {
	var recent, recentRefused, before, beforeRefused int
	for _, event := range events {
		age := now.Sub(event.Time)
		refused := event.Decision == "refused"
		switch {
		case age < 0:
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
	}
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
