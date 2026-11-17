// Admin API advice and alerts: the fixed checks applied to the current
// generation, observed traffic and the security log.

package admin

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// handleAdvice answers the configuration warnings and unused permissions for
// the generation in force, or for a stored draft compiled with the active
// overrides.
func (s *Server) handleAdvice(w http.ResponseWriter, r *http.Request, who caller) {
	g := s.control.Current()
	var candidate *int64
	if text := r.URL.Query().Get("candidate"); text != "" {
		id, err := strconv.ParseInt(text, 10, 64)
		if err != nil || id < 1 {
			adminError(w, http.StatusBadRequest, "bad_request", "candidate")
			return
		}
		var ok bool
		if _, g, ok = s.candidateGeneration(w, r, who, id); !ok {
			return
		}
		candidate = &id
	} else if g == nil || g.Expired(compile.TrustedNow()) {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	if !s.scanLog(r.Context()) {
		return
	}
	defer s.scanDone()
	// The warnings need no log file, so an unreadable log withholds only the
	// unused permissions.
	unused, err := s.unusedPermits(r.Context(), g)
	if r.Context().Err() != nil {
		return // the client has gone
	}
	if err != nil {
		s.logger.Error("reading the security log for advice", "error", err)
		s.observations.AdminFailed(monitor.FailLog)
		unused = monitor.UnreadLog()
	}
	pipeline.WriteJSON(w, http.StatusOK, map[string]any{
		"rules":          monitor.AdviceRules,
		"generation":     g.ID,
		"candidate":      candidate,
		"warnings":       monitor.ConfigurationWarnings(g, s.plain),
		"unused_permits": unused,
	})
}

// unusedPermits reads the security log files for the unused-permission advice.
func (s *Server) unusedPermits(ctx context.Context, g *compile.Generation) (monitor.UnusedReport, error) {
	_, _, _, kept := s.audit.Usage()
	files, missing, err := monitor.LogFiles(s.audit.Path(), kept)
	if err != nil {
		return monitor.UnusedReport{}, err
	}
	use, err := s.summaries.PermitUse(ctx, filepath.Dir(s.audit.Path()), files, monitor.ExportScan)
	if err != nil {
		return monitor.UnusedReport{}, err
	}
	return monitor.UnusedPermissions(g, use, missing, time.Now()), nil
}

// handleAlerts evaluates the alert rules when read; nothing is evaluated per
// request.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request, who caller) {
	now := time.Now()
	items := []monitor.Finding{}
	if spike := monitor.RefusalSpike(s.observations.Snapshot(), now); spike != nil {
		items = append(items, *spike)
	}
	if s.audit.Failed() {
		items = append(items, monitor.Finding{ID: "A2", Severity: "critical", Object: "security_log", Message: "The security log cannot be written, so the gateway refuses requests it cannot record."})
	}
	used, budget := s.audit.Budget()
	rate, err := s.writeRate(now)
	if err != nil {
		s.logger.Error("reading the security log's write rate", "error", err)
		s.observations.AdminFailed(monitor.FailLog)
	}
	if alert := logFilling(used, budget, rate, s.audit.Evicts()); alert != nil {
		if err != nil {
			alert.Message += " The current write rate could not be read."
		}
		items = append(items, *alert)
	}
	if float64(s.limiter.Size()) >= monitor.NearlyFull*float64(s.limiter.Capacity()) {
		items = append(items, monitor.Finding{ID: "A4", Severity: "medium", Object: "rate_counters", Message: "Rate limit counters are nearly full. When they run out, requests that need a new counter are refused."})
	}
	monitor.SortFindings(items)
	pipeline.WriteJSON(w, http.StatusOK, map[string]any{"rules": monitor.AdviceRules, "evaluated_at": now.UTC(), "alerts": items})
}

// writeRate is the active audit file's recent write rate in bytes per second,
// read over its last RateMinBytes; 0 when unknown, with the error when the
// file could not be read. A log that evicts never fills, so its file is not
// read.
func (s *Server) writeRate(now time.Time) (float64, error) {
	active, _, _, _ := s.audit.Usage()
	if s.audit.Evicts() || active < monitor.RateMinBytes {
		return 0, nil
	}
	recent, first, err := monitor.RecentRecord(s.audit.Path(), monitor.RateMinBytes)
	if err != nil {
		return 0, err
	}
	return pace(active, recent, first, now), nil
}

// pace is the bytes written since first, per second; 0 while the active file
// holds less than RateMinBytes or without a usable start.
func pace(active, bytes int64, first, now time.Time) float64 {
	elapsed := now.Sub(first).Seconds()
	if active < monitor.RateMinBytes || first.IsZero() || elapsed <= 0 {
		return 0
	}
	return float64(bytes) / elapsed
}

// logFilling is alert A3: the security log's files hold at least Filling
// (medium) or NearlyFull (critical) of its budget, files × file size, or at
// rate bytes per second (0: unknown) the rest of the budget lasts less than
// FillingTime or NearlyFullTime. A log that evicts never fills.
func logFilling(used, budget int64, rate float64, evicts bool) *monitor.Finding {
	if evicts || budget <= 0 {
		return nil
	}
	share := float64(used) / float64(budget)
	left := -1.0
	if rate > 0 {
		left = float64(max(budget-used, 0)) / rate
	}
	soon := func(limit time.Duration) bool { return left >= 0 && left < limit.Seconds() }
	var message string
	switch {
	case share >= monitor.NearlyFull:
		message = "The security log is nearly full. Move earlier log files to an archive now, or the gateway will stop accepting requests when it fills."
	case soon(monitor.NearlyFullTime):
		message = "The security log will be full soon. Move earlier log files to an archive now, or the gateway will stop accepting requests when it fills."
	case share >= monitor.Filling:
		message = "The security log has used most of its space. Move earlier log files to an archive before it fills."
	case soon(monitor.FillingTime):
		message = "The security log is filling quickly. Move earlier log files to an archive before it fills."
	default:
		return nil
	}
	severity := "medium"
	if share >= monitor.NearlyFull || soon(monitor.NearlyFullTime) {
		severity = "critical"
	}
	if left >= 0 {
		message += " At the current rate it is full in " + about(left) + "."
	}
	return &monitor.Finding{ID: "A3", Severity: severity, Object: "security_log", Message: message}
}

// about words a number of seconds as minutes, hours or days.
func about(seconds float64) string {
	minutes := math.Round(seconds / 60)
	switch {
	case minutes < 1:
		return "less than a minute"
	case minutes == 1:
		return "about 1 minute"
	case minutes < 120:
		return fmt.Sprintf("about %.0f minutes", minutes)
	case minutes < 48*60:
		return fmt.Sprintf("about %.0f hours", math.Round(minutes/60))
	default:
		return fmt.Sprintf("about %.0f days", math.Round(minutes/(24*60)))
	}
}
