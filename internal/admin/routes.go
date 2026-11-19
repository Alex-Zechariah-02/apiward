// The Admin API's routes: the table of endpoints with the permission each
// needs, and the wrapper that authenticates, checks origin and CSRF, and
// records reads before a handler runs.

package admin

import (
	"crypto/subtle"
	"net/http"
	"slices"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Handler routes every Admin API endpoint behind the Host check.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/health", s.handleHealth)
	mux.HandleFunc("POST /admin/enrol", s.handleEnrol)
	mux.HandleFunc("POST /admin/session", s.handleLogin)
	if s.jwks != nil {
		// Public keys need no session: upstreams and operators fetch them.
		mux.HandleFunc("GET "+pipeline.JWKSPath, s.handleJWKS)
	}

	for _, entry := range []route{
		{"GET /admin/session", 0, false, s.handleWhoAmI},
		{"DELETE /admin/session", 0, false, s.handleLogout},
		{"PUT /admin/password", 0, false, s.handlePassword},
		{"GET /admin/status", store.PermRead, false, s.handleStatus},
		{"GET /admin/policy", store.PermRead, false, s.handlePolicy},
		{"GET /admin/revisions", store.PermRead, false, s.handleRevisions},
		{"GET /admin/revisions/{id}", store.PermRead, false, s.handleRevision},
		{"GET /admin/keys", store.PermRead, false, s.handleKeys},
		{"POST /admin/keys/reload", store.PermManagePolicy, false, s.handleReloadKeys},
		{"GET /admin/tls-profiles", store.PermRead, false, s.handleProfiles},
		{"GET /admin/blocked-accounts", store.PermRead, false, s.handleBlockedAccounts},
		{"PUT /admin/blocked-accounts/{subject}", store.PermManageSubjects, false, s.handleBlockAccount},
		{"DELETE /admin/blocked-accounts/{subject}", store.PermManageSubjects, false, s.handleUnblockAccount},
		{"GET /admin/blocked-addresses", store.PermRead, false, s.handleBlockedAddresses},
		{"PUT /admin/blocked-addresses/{range}", store.PermManageSubjects, false, s.handleBlockAddress},
		{"DELETE /admin/blocked-addresses/{range}", store.PermManageSubjects, false, s.handleUnblockAddress},
		{"GET /admin/administrators", store.PermRead, false, s.handleAdministrators},
		{"GET /admin/events", store.PermRead, false, s.handleEvents},
		{"GET /admin/events/stream", store.PermRead, false, s.handleEventStream},
		{"GET /admin/traffic", store.PermRead, false, s.handleTraffic},
		{"GET /admin/limits", store.PermRead, false, s.handleLimits},
		{"POST /admin/access-check", store.PermRead, true, s.handleAccessCheck},
		{"GET /admin/advice", store.PermRead, false, s.handleAdvice},
		{"GET /admin/alerts", store.PermRead, false, s.handleAlerts},
		{"POST /admin/candidates/{id}/impact", store.PermRead, true, s.handleImpact},
		{"GET /admin/candidates", store.PermRead, false, s.handleCandidates},
		{"GET /admin/candidates/{id}", store.PermRead, false, s.handleCandidate},
		{"POST /admin/candidates", store.PermManagePolicy, false, s.handlePostCandidate},
		{"DELETE /admin/candidates/{id}", store.PermManagePolicy, false, s.handleWithdrawCandidate},
		{"POST /admin/genesis", store.PermManagePolicy, false, s.handleEstablish("genesis")},
		{"POST /admin/recovery-base", store.PermManagePolicy, false, s.handleEstablish("recovery_base")},
		{"GET /admin/provisional", store.PermRead, false, s.handleProvisional},
		{"POST /admin/provisional", store.PermManagePolicy, false, s.handleActivate},
		{"POST /admin/provisional/confirm", store.PermManagePolicy, false, s.handleResolve("cpa.confirm", store.DispositionConfirmed)},
		{"POST /admin/provisional/rollback", store.PermManagePolicy, false, s.handleResolve("cpa.rollback", store.DispositionRolledBack)},
		{"GET /admin/activations", store.PermReadHistory, false, s.handleActivations},
		{"GET /admin/overrides", store.PermRead, false, s.handleOverrides},
		{"GET /admin/overrides/history", store.PermReadHistory, false, s.handleOverrideHistory},
		{"GET /admin/overrides/{id}", store.PermRead, false, s.handleOverride},
		{"POST /admin/overrides/validate", store.PermManagePolicy, true, s.handleValidateOverride},
		{"POST /admin/overrides", store.PermManagePolicy, false, s.handleCreateOverride},
		{"DELETE /admin/overrides/{id}", store.PermManagePolicy, false, s.handleRevokeOverride},
		{"GET /admin/history", store.PermReadHistory, false, s.handleHistory},
		{"GET /admin/history/{id}", store.PermReadHistory, false, s.handleHistoryEntry},
		{"GET /admin/security-log", store.PermReadHistory, false, s.handleSecurityLog},
	} {
		s.route(mux, entry)
	}
	if s.ui != nil {
		// Only the page and its flat assets directory exist: no fallback page
		// can answer an unknown path, so an API path never receives HTML.
		mux.Handle("GET /{$}", s.ui)
		mux.Handle("GET /assets/{file}", s.ui)
	}
	registerTestRoutes(s, mux)
	return s.checkHost(detachWrites(mux))
}

// route is one authenticated endpoint: its pattern, the permission it needs
// (0: any administrator, for their own session) and its handler. read marks
// a POST that changes nothing, sent as POST only because its question is a
// request body; it is recorded as a read like any GET.
type route struct {
	pattern  string
	required store.Permission
	read     bool
	handler  adminHandler
}

// route registers a handler that runs only for an authenticated administrator
// holding the required permission. A state-changing request also needs the
// admin origin and the session's CSRF token.
func (s *Server) route(mux *http.ServeMux, entry route) {
	required, handler := entry.required, entry.handler
	mux.HandleFunc(entry.pattern, func(w http.ResponseWriter, r *http.Request) {
		who, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		if unsafeMethod(r.Method) {
			if !s.sameOrigin(r) {
				s.refuse(w, r, http.StatusForbidden, "forbidden", "bad_origin", &who)
				return
			}
			token := r.Header.Get(csrfHeader)
			if subtle.ConstantTimeCompare([]byte(token), []byte(who.session.CSRF)) != 1 {
				s.refuse(w, r, http.StatusForbidden, "forbidden", "csrf", &who)
				return
			}
		}
		if who.admin.Permissions&required != required {
			s.refuse(w, r, http.StatusForbidden, "forbidden", "permission", &who)
			return
		}
		quiet := r.Method == http.MethodGet && slices.Contains(s.config.IgnoredReads, r.URL.Path)
		if (!unsafeMethod(r.Method) || entry.read) && !quiet {
			s.audit.Record(audit.Event{Kind: "admin.read", Method: r.Method, Path: r.URL.Path, Actor: who.admin.Name, Session: who.session.Reference})
		}
		handler(w, r, who)
	})
}
