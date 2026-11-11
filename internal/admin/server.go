// The Admin API server: routing, authentication, Host, Origin and CSRF checks.

package admin

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

const (
	maxAdminBody = 4 << 10
	// policyMargin is the room a request body has beyond the policy it
	// carries, for its envelope and the policy's indentation.
	policyMargin    = 16 << 10
	defaultPageSize = 50
	maxPageSize     = 100
	sessionCookie   = "__Host-gateway-admin"
	csrfHeader      = "X-CSRF-Token"
	minKeyLength    = 16
	maxKeyLength    = 64
)

// caller is the authenticated administrator of one admin request.
type caller struct {
	admin   store.Administrator
	session session.Session
	token   string
}

type adminHandler func(w http.ResponseWriter, r *http.Request, who caller)

// Server is the Admin API: routing, authentication, the Host, Origin and
// CSRF checks, the login throttle, password hashing and every handler. It
// changes state only through the controller's exported operations and reads
// the database only through store.Reads.
type Server struct {
	control      *controller.Controller
	config       controller.Config
	store        store.Reads
	audit        *audit.AuditLog
	observations *monitor.Observations
	limiter      *pipeline.Limiter
	sessions     *session.Table
	throttle     *throttle
	hashing      chan struct{} // bounds concurrent password hashing
	ui           http.Handler  // the dashboard files; nil when none are configured
	plain        bool          // the gateway serves the data plane itself over plain HTTP
	jwks         []byte        // the identity assertion's public key set; nil when none is signed
	logger       *slog.Logger
}

// Deps is what the Admin API serves: an opened controller, the data plane's
// rate counters (for the limits view), the dashboard files (nil: none) and
// the logger. Plain is true when the gateway serves the data plane itself
// over plain HTTP, so HSTS is never sent; false when a host program owns it.
// JWKS is the public key set of the identity assertion (nil: none signed).
type Deps struct {
	Control *controller.Controller
	Limiter *pipeline.Limiter
	UI      http.Handler
	Plain   bool
	Logger  *slog.Logger
	JWKS    []byte
}

// New returns the Admin API of d.Control.
func New(d Deps) *Server {
	c := d.Control
	return &Server{
		control: c, config: c.Settings(), store: c.Reads(), audit: c.Audit(),
		observations: c.Observations(), limiter: d.Limiter, sessions: c.Sessions(),
		throttle: newThrottle(), hashing: make(chan struct{}, maxHashing), ui: d.UI, plain: d.Plain, jwks: d.JWKS, logger: d.Logger,
	}
}

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

	s.route(mux, "GET /admin/session", 0, s.handleWhoAmI)
	s.route(mux, "DELETE /admin/session", 0, s.handleLogout)
	s.route(mux, "PUT /admin/password", 0, s.handlePassword)
	s.route(mux, "GET /admin/status", store.PermRead, s.handleStatus)
	s.route(mux, "GET /admin/policy", store.PermRead, s.handlePolicy)
	s.route(mux, "GET /admin/revisions", store.PermRead, s.handleRevisions)
	s.route(mux, "GET /admin/revisions/{id}", store.PermRead, s.handleRevision)
	s.route(mux, "GET /admin/keys", store.PermRead, s.handleKeys)
	s.route(mux, "POST /admin/keys/reload", store.PermManagePolicy, s.handleReloadKeys)
	s.route(mux, "GET /admin/tls-profiles", store.PermRead, s.handleProfiles)
	s.route(mux, "GET /admin/blocked-accounts", store.PermRead, s.handleBlockedAccounts)
	s.route(mux, "PUT /admin/blocked-accounts/{subject}", store.PermManageSubjects, s.handleBlockAccount)
	s.route(mux, "DELETE /admin/blocked-accounts/{subject}", store.PermManageSubjects, s.handleUnblockAccount)
	s.route(mux, "GET /admin/blocked-addresses", store.PermRead, s.handleBlockedAddresses)
	s.route(mux, "PUT /admin/blocked-addresses/{range}", store.PermManageSubjects, s.handleBlockAddress)
	s.route(mux, "DELETE /admin/blocked-addresses/{range}", store.PermManageSubjects, s.handleUnblockAddress)
	s.route(mux, "GET /admin/administrators", store.PermRead, s.handleAdministrators)
	s.route(mux, "GET /admin/events", store.PermRead, s.handleEvents)
	s.route(mux, "GET /admin/events/stream", store.PermRead, s.handleEventStream)
	s.route(mux, "GET /admin/traffic", store.PermRead, s.handleTraffic)
	s.route(mux, "GET /admin/limits", store.PermRead, s.handleLimits)
	s.route(mux, "POST /admin/access-check", store.PermRead, s.handleAccessCheck)
	s.route(mux, "GET /admin/advice", store.PermRead, s.handleAdvice)
	s.route(mux, "GET /admin/alerts", store.PermRead, s.handleAlerts)
	s.route(mux, "POST /admin/candidates/{id}/impact", store.PermRead, s.handleImpact)
	s.route(mux, "GET /admin/candidates", store.PermRead, s.handleCandidates)
	s.route(mux, "GET /admin/candidates/{id}", store.PermRead, s.handleCandidate)
	s.route(mux, "POST /admin/candidates", store.PermManagePolicy, s.handlePostCandidate)
	s.route(mux, "DELETE /admin/candidates/{id}", store.PermManagePolicy, s.handleWithdrawCandidate)
	s.route(mux, "POST /admin/genesis", store.PermManagePolicy, s.handleEstablish("genesis"))
	s.route(mux, "POST /admin/recovery-base", store.PermManagePolicy, s.handleEstablish("recovery_base"))
	s.route(mux, "GET /admin/provisional", store.PermRead, s.handleProvisional)
	s.route(mux, "POST /admin/provisional", store.PermManagePolicy, s.handleActivate)
	s.route(mux, "POST /admin/provisional/confirm", store.PermManagePolicy, s.handleResolve("cpa.confirm", store.DispositionConfirmed))
	s.route(mux, "POST /admin/provisional/rollback", store.PermManagePolicy, s.handleResolve("cpa.rollback", store.DispositionRolledBack))
	s.route(mux, "GET /admin/activations", store.PermReadHistory, s.handleActivations)
	s.route(mux, "GET /admin/overrides", store.PermRead, s.handleOverrides)
	s.route(mux, "GET /admin/overrides/history", store.PermReadHistory, s.handleOverrideHistory)
	s.route(mux, "GET /admin/overrides/{id}", store.PermRead, s.handleOverride)
	s.route(mux, "POST /admin/overrides/validate", store.PermManagePolicy, s.handleValidateOverride)
	s.route(mux, "POST /admin/overrides", store.PermManagePolicy, s.handleCreateOverride)
	s.route(mux, "DELETE /admin/overrides/{id}", store.PermManagePolicy, s.handleRevokeOverride)
	s.route(mux, "GET /admin/history", store.PermReadHistory, s.handleHistory)
	s.route(mux, "GET /admin/history/{id}", store.PermReadHistory, s.handleHistoryEntry)
	s.route(mux, "GET /admin/security-log", store.PermReadHistory, s.handleSecurityLog)
	if s.ui != nil {
		// Only the page and its flat assets directory exist: no fallback page
		// can answer an unknown path, so an API path never receives HTML.
		mux.Handle("GET /{$}", s.ui)
		mux.Handle("GET /assets/{file}", s.ui)
	}
	registerTestRoutes(s, mux)
	return s.checkHost(detachWrites(mux))
}

// checkHost refuses any request whose Host is not exactly the admin listener
// address, so a name that resolves to loopback cannot be used to reach the
// API from another site's pages (DNS rebinding).
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != s.config.AdminListen {
			s.refuse(w, r, http.StatusBadRequest, "bad_request", "bad_host", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// detachWrites keeps a state-changing request running when its client
// disconnects: a change is committed in steps, and stopping between them
// would leave its outcome unrecorded and fail the audit log. Reads keep
// their cancellation, so a closed event stream ends.
func detachWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unsafeMethod(r.Method) {
			r = r.WithContext(context.WithoutCancel(r.Context()))
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin requires the Origin header of a state-changing request to name
// the admin listener itself. A request without one is refused: a browser
// always sends it on such requests, and other clients can.
func (s *Server) sameOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	return len(origins) == 1 && origins[0] == "http://"+s.config.AdminListen
}

func unsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead
}

// route registers a handler that runs only for an authenticated administrator
// holding the required permission (0: any administrator, for their own
// session). A state-changing request also needs the admin origin and the
// session's CSRF token.
func (s *Server) route(mux *http.ServeMux, pattern string, required store.Permission, handler adminHandler) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
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
		if !unsafeMethod(r.Method) {
			s.audit.Record(audit.Event{Kind: "admin.read", Method: r.Method, Path: r.URL.Path, Actor: who.admin.Name, Session: who.session.Reference})
		}
		handler(w, r, who)
	})
}

// authenticate resolves the session cookie to a live session and re-reads the
// administrator, so a quarantined administrator or a replaced credential loses
// access at once.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (caller, bool) {
	reason := "no_session"
	var who caller
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		who.token = cookie.Value
		who.session, reason = s.sessions.Lookup(cookie.Value, time.Now())
	}
	if reason == "" {
		admin, found, err := s.store.Administrator(r.Context(), who.session.Admin)
		if err != nil {
			s.logger.Error("reading administrator", "error", err)
			adminError(w, http.StatusServiceUnavailable, "unavailable", "")
			return caller{}, false
		}
		who.admin = admin
		if !found || admin.Status != "active" || admin.Credential != who.session.Credential {
			s.sessions.Revoke(who.token)
			reason = "credential_changed"
		}
	}
	if reason != "" {
		s.refuse(w, r, http.StatusUnauthorized, "unauthenticated", reason, nil)
		return caller{}, false
	}
	return who, true
}

// refuse answers a refused admin request and records why. Only the error code
// reaches the client.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, status int, code, reason string, who *caller) {
	event := audit.Event{Kind: "admin.rejected", Method: r.Method, Path: r.URL.Path, Status: status, Reason: reason}
	if who != nil {
		event.Kind, event.Actor, event.Session = "admin.denied", who.admin.Name, who.session.Reference
	}
	s.audit.Record(event)
	adminError(w, status, code, "")
}

// adminError answers with an error code and, where it helps the client, the
// name of the offending field. Nothing else about the failure is disclosed.
func adminError(w http.ResponseWriter, status int, code, field string) {
	body := map[string]string{"error": code}
	if field != "" {
		body["field"] = field
	}
	pipeline.WriteJSON(w, status, body)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	state := s.control.State()
	if state != store.ModeNormal && state != store.ModeBootstrap && state != store.ModeRecovery {
		state = "unavailable"
	}
	pipeline.WriteJSON(w, http.StatusOK, map[string]string{"state": state})
}

// policyBody bounds a request body that carries a whole policy.
func (s *Server) policyBody() int64 {
	return int64(s.config.Limits.PolicyBytes) + policyMargin
}
