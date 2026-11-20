// The Admin API's limits view: each built-in bound with its current use,
// read from the component that owns it.

package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// handleLimits reports each built-in limit with its current use, so an
// administrator can see one coming before it is reached. Every figure is read
// from the component that owns it; nothing here changes a limit. The list is
// fixed: one member per built-in bound an administrator can run into.
func (s *Server) handleLimits(w http.ResponseWriter, r *http.Request, who caller) {
	active, blocked, addresses := 0, 0, 0
	if g := s.control.Current(); g != nil {
		active = len(g.Overrides)
	}
	if list := s.control.Blocked(); list != nil {
		blocked = len(*list)
	}
	if list := s.control.Addresses(); list != nil {
		addresses = len(*list)
	}
	auditBytes, auditBytesLimit, auditFiles, auditFilesLimit := s.audit.Usage()
	archive, _ := s.audit.Archive()
	document, err := s.confirmedBytes(r.Context())
	if err != nil {
		s.fail(w, r, &who, "unavailable", monitor.FailStore, err)
		return
	}
	limit := func(used, max int64) map[string]int64 { return map[string]int64{"used": used, "max": max} }
	pipeline.WriteJSON(w, http.StatusOK, map[string]any{
		"policy_bytes":           limit(document, int64(s.config.Limits.PolicyBytes)),
		"temporary_rules":        limit(int64(active), store.MaxActiveOverrides),
		"blocked_accounts":       limit(int64(blocked), store.MaxBlockedAccounts),
		"blocked_addresses":      limit(int64(addresses), store.MaxBlockedAddresses),
		"live_views":             limit(int64(s.observations.Viewers()), monitor.MaxStreams),
		"administrator_sessions": limit(int64(s.sessions.Count(time.Now())), session.Max),
		"audit_files":            limit(auditFiles, auditFilesLimit),
		"audit_active_bytes":     limit(auditBytes, auditBytesLimit),
		"audit_archive_bytes":    limit(archive.Bytes, archive.Budget),
		"rate_counters":          limit(int64(s.limiter.Size()), int64(s.limiter.Capacity())),
		"recent_requests":        limit(int64(s.observations.Retained()), int64(s.observations.Window())),
	})
}

// revisionSize is the stored size of one revision's document; revisions
// never change, so it is read once per confirmed revision.
type revisionSize struct{ id, bytes int64 }

// confirmedBytes is the stored size of the confirmed policy document; 0 when
// no policy is confirmed.
func (s *Server) confirmedBytes(ctx context.Context) (int64, error) {
	a, err := s.store.Load(ctx)
	// A quarantine after a restore keeps the confirmed document, so only
	// a deployment that never confirmed one reports 0.
	if err != nil || a.Confirmed == 0 {
		return 0, err
	}
	if known := s.confirmedSize.Load(); known != nil && known.id == a.Confirmed {
		return known.bytes, nil
	}
	revision, _, err := s.store.Revision(ctx, a.Confirmed)
	if err != nil {
		return 0, err
	}
	size := int64(len(revision.Document))
	s.confirmedSize.Store(&revisionSize{a.Confirmed, size})
	return size, nil
}
