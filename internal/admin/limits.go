package admin

import (
	"net/http"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// handleLimits reports each built-in limit with its current use, so an
// administrator can see one coming before it is reached. Every figure is read
// from the component that owns it; nothing here changes a limit.
func (s *Server) handleLimits(w http.ResponseWriter, r *http.Request, who caller) {
	active := 0
	if g := s.control.Current(); g != nil {
		active = len(g.Overrides)
	}
	auditBytes, auditBytesLimit, auditFiles, auditFilesLimit := s.audit.Usage()
	limit := func(used, max int64) map[string]int64 { return map[string]int64{"used": used, "max": max} }
	pipeline.WriteJSON(w, http.StatusOK, map[string]any{
		"temporary_rules":        limit(int64(active), store.MaxActiveOverrides),
		"live_views":             limit(int64(s.observations.Viewers()), monitor.MaxStreams),
		"administrator_sessions": limit(int64(s.sessions.Count()), session.Max),
		"audit_files":            limit(auditFiles, auditFilesLimit),
		"audit_active_bytes":     limit(auditBytes, auditBytesLimit),
		"rate_counters":          limit(int64(s.limiter.Size()), int64(s.limiter.Capacity())),
		"recent_requests":        limit(int64(s.observations.Retained()), monitor.RecentLimit),
	})
}
