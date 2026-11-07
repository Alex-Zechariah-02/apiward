// Admin API advice and alerts: the fixed checks applied to the current
// generation, observed traffic and the security log.

package gateway

import (
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
func (c *Controller) handleAdvice(w http.ResponseWriter, r *http.Request, who caller) {
	g := c.Current()
	var candidate *int64
	if text := r.URL.Query().Get("candidate"); text != "" {
		id, err := strconv.ParseInt(text, 10, 64)
		if err != nil || id < 1 {
			adminError(w, http.StatusBadRequest, "bad_request", "candidate")
			return
		}
		var ok bool
		if _, g, ok = c.candidateGeneration(w, r, id); !ok {
			return
		}
		candidate = &id
	} else if g == nil || g.Expired(compile.TrustedNow()) {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	files, missing, err := monitor.LogFiles(c.audit.Path())
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	use, err := monitor.PermitUse(filepath.Dir(c.audit.Path()), files, monitor.ExportScan)
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	pipeline.WriteJSON(w, http.StatusOK, map[string]any{
		"rules":          monitor.AdviceRules,
		"generation":     g.ID,
		"candidate":      candidate,
		"warnings":       monitor.ConfigurationWarnings(g),
		"unused_permits": monitor.UnusedPermissions(g, use, missing, time.Now()),
	})
}

// handleAlerts evaluates the alert rules when read; nothing is evaluated per
// request.
func (c *Controller) handleAlerts(w http.ResponseWriter, r *http.Request, who caller) {
	now := time.Now()
	items := []monitor.Finding{}
	if spike := monitor.RefusalSpike(c.observations.Snapshot(), now); spike != nil {
		items = append(items, *spike)
	}
	if c.audit.Failed() {
		items = append(items, monitor.Finding{ID: "A2", Severity: "critical", Object: "security_log", Message: "The security log cannot be written, so the gateway refuses requests it cannot record."})
	}
	if active, activeLimit, files, filesLimit := c.audit.Usage(); files >= filesLimit && float64(active) >= monitor.NearlyFull*float64(activeLimit) {
		items = append(items, monitor.Finding{ID: "A3", Severity: "high", Object: "security_log", Message: "The security log is nearly full. Move earlier log files to an archive before it fills, or the gateway will stop accepting requests."})
	}
	if float64(c.limiter.Size()) >= monitor.NearlyFull*float64(c.limiter.Capacity()) {
		items = append(items, monitor.Finding{ID: "A4", Severity: "medium", Object: "rate_counters", Message: "Rate limit counters are nearly full. When they run out, requests that need a new counter are refused."})
	}
	monitor.SortFindings(items)
	pipeline.WriteJSON(w, http.StatusOK, map[string]any{"rules": monitor.AdviceRules, "evaluated_at": now.UTC(), "alerts": items})
}
