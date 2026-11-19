// The Admin API server: its state, authentication, the Host check and health.

package admin

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

const (
	// maxAdminBody holds every request body except a whole policy: they are
	// a few named fields, the largest a temporary rule with its reason.
	maxAdminBody = 4 << 10
	// policyFactor bounds a body carrying a policy at this many times the
	// policy limit: a pretty-printed policy at the limit, with one permit
	// per line, takes up to about twice it, and the envelope little more.
	policyFactor = 4
	// answerRoom is the part of the admin write limit kept for writing the
	// answer of a state-changing request.
	answerRoom = 2 * time.Second
	// A default page fills one Dashboard table; a client may ask for twice
	// that. Pages keep each read and answer small however long a list grows.
	defaultPageSize = 50
	maxPageSize     = 100
	sessionCookie   = "__Host-gateway-admin"
	csrfHeader      = "X-CSRF-Token"
	// An Idempotency-Key of 16 characters from its 64-letter alphabet holds
	// 96 random bits; 64 bounds the transition ID it becomes part of.
	minKeyLength = 16
	maxKeyLength = 64
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
	summaries    monitor.Summaries // security log files read for advice
	// confirmedSize is the confirmed document's size for the limits view.
	confirmedSize atomic.Pointer[revisionSize]
	limiter       *pipeline.Limiter
	sessions      *session.Table
	throttle      *throttle
	hashing       chan struct{} // bounds concurrent password hashing
	scans         chan struct{} // bounds concurrent security log scans
	ui            http.Handler  // the dashboard files; nil when none are configured
	plain         bool          // the gateway serves the data plane itself over plain HTTP
	hostServed    bool          // a host program serves the data plane (library mode)
	jwks          []byte        // the identity assertion's public key set; nil when none is signed
	logger        *slog.Logger
}

// Deps is what the Admin API serves: an opened controller, the data plane's
// rate counters (for the limits view), the dashboard files (nil: none) and
// the logger. Plain is true when the gateway serves the data plane itself
// over plain HTTP, so HSTS is never sent; false when a host program owns it.
// JWKS is the public key set of the identity assertion (nil: none signed).
// HostServed is true when a host program serves the data plane, so the
// advice says the gateway cannot confirm its transport.
type Deps struct {
	Control    *controller.Controller
	Limiter    *pipeline.Limiter
	UI         http.Handler
	Plain      bool
	Logger     *slog.Logger
	JWKS       []byte
	HostServed bool
}

// New returns the Admin API of d.Control.
func New(d Deps) *Server {
	c := d.Control
	return &Server{
		control: c, config: c.Settings(), store: c.Reads(), audit: c.Audit(),
		observations: c.Observations(), limiter: d.Limiter, sessions: c.Sessions(),
		throttle: newThrottle(), hashing: make(chan struct{}, maxHashing), scans: make(chan struct{}, maxLogScans), ui: d.UI, plain: d.Plain, hostServed: d.HostServed, jwks: d.JWKS, logger: d.Logger,
	}
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
// would leave its outcome unrecorded. It still ends at the admin listener's
// write limit, which no answer can outlast, so a stalled database call cannot
// hold the controller for good; the controller's audit records keep their
// own wait. Reads keep their cancellation, so a closed event stream ends.
func detachWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unsafeMethod(r.Method) {
			// Ends answerRoom before the listener's write limit, so a change
			// that used its whole bound can still be answered.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), controller.AdminWriteTimeout-answerRoom)
			defer cancel()
			r = r.WithContext(ctx)
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
			s.fail(w, r, nil, "unavailable", monitor.FailStore, err)
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	state := s.control.State()
	if state != store.ModeNormal && state != store.ModeBootstrap && state != store.ModeRecovery {
		state = "unavailable"
	}
	// A health check that reads only the status code sees an unavailable
	// gateway, which refuses every request, as not ready.
	status := http.StatusOK
	if state == "unavailable" {
		status = http.StatusServiceUnavailable
	}
	pipeline.WriteJSON(w, status, map[string]string{"state": state})
}

// policyBody bounds a request body that carries a whole policy.
func (s *Server) policyBody() int64 {
	return int64(s.config.Limits.PolicyBytes) * policyFactor
}
