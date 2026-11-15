// Admin API enrolment, sign-in, session and password handlers.

package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// acquireHashing takes one of the bounded password-hashing slots.
func (s *Server) acquireHashing() bool {
	select {
	case s.hashing <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseHashing() { <-s.hashing }

func (s *Server) handleEnrol(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		s.refuse(w, r, http.StatusForbidden, "forbidden", "bad_origin", nil)
		return
	}
	var body struct {
		Name     string `json:"name"`
		Secret   string `json:"secret"`
		Password string `json:"password"`
	}
	if !decodeBody(w, r, maxAdminBody, &body) {
		return
	}
	if !store.IsAdminName(body.Name) {
		adminError(w, http.StatusBadRequest, "bad_request", "name")
		return
	}
	if !validPassword(body.Password) {
		adminError(w, http.StatusBadRequest, "bad_request", "password")
		return
	}
	if s.store == nil {
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	now := time.Now()
	try, reason := s.throttle.begin(body.Name, r, now)
	if reason != "" {
		s.refuse(w, r, http.StatusTooManyRequests, "too_many_attempts", reason, nil)
		return
	}
	e, found, err := s.store.Enrolment(r.Context(), session.Hash(body.Secret))
	if err != nil {
		try.abandoned()
		s.fail(w, r, nil, "unavailable", monitor.FailStore, err)
		return
	}
	if !found || e.Name != body.Name || !now.Before(e.ExpiresAt) {
		try.failed(now)
		s.refuse(w, r, http.StatusUnauthorized, "unauthenticated", "enrolment_invalid", nil)
		return
	}
	if !s.acquireHashing() {
		try.abandoned()
		s.fail(w, r, nil, "busy", monitor.FailBusy, nil)
		return
	}
	passwordHash := hashPassword(body.Password)
	s.releaseHashing()

	outcome, status := s.control.Enrol(r.Context(), e, passwordHash)
	if status != http.StatusOK {
		try.abandoned()
		pipeline.WriteJSON(w, status, outcome)
		return
	}
	try.succeeded()
	pipeline.WriteJSON(w, http.StatusCreated, map[string]any{"name": e.Name, "permissions": e.Permissions.Names()})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		s.refuse(w, r, http.StatusForbidden, "forbidden", "bad_origin", nil)
		return
	}
	var body struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !decodeBody(w, r, maxAdminBody, &body) {
		return
	}
	if s.store == nil {
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	now := time.Now()
	try, reason := s.throttle.begin(body.Name, r, now)
	if reason != "" {
		s.refuse(w, r, http.StatusTooManyRequests, "too_many_attempts", reason, nil)
		return
	}
	admin, found, err := s.store.Administrator(r.Context(), body.Name)
	if err != nil {
		try.abandoned()
		s.fail(w, r, nil, "unavailable", monitor.FailStore, err)
		return
	}

	// An unknown or quarantined name is verified against a dummy hash, so the
	// answer and its timing are the same as for a wrong password.
	active := found && admin.Status == "active"
	encoded := dummyHash()
	if active {
		encoded = admin.Password
	}
	if !s.acquireHashing() {
		try.abandoned()
		s.fail(w, r, nil, "busy", monitor.FailBusy, nil)
		return
	}
	verified := verifyPassword(encoded, body.Password) && active
	s.releaseHashing()
	if !verified {
		try.failed(now)
		s.refuse(w, r, http.StatusUnauthorized, "unauthenticated", "bad_credentials", nil)
		return
	}
	try.succeeded()

	token, created, err := s.sessions.Create(admin.Name, admin.Credential, now)
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "session_limit", "")
		return
	}
	// The sign-in record is durable before the client holds the session.
	signedIn := audit.Event{Kind: "admin.authenticated", Method: r.Method, Path: r.URL.Path, Actor: admin.Name, Session: created.Reference}
	if err := s.commitAudit(r.Context(), signedIn); err != nil {
		s.sessions.Revoke(token)
		s.fail(w, r, nil, "unavailable", monitor.FailAudit, err)
		return
	}
	// Host-only, HTTPS-only for browsers, hidden from scripts, never sent
	// cross-site; no Max-Age, as the session table decides the lifetime.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	pipeline.WriteJSON(w, http.StatusCreated, sessionView(admin, created))
}

// commitAudit records e and waits for it to be durable, within the
// configured audit wait.
func (s *Server) commitAudit(ctx context.Context, e audit.Event) error {
	ctx, cancel := context.WithTimeout(ctx, s.config.AuditTimeout)
	defer cancel()
	return s.audit.Commit(ctx, e)
}

func sessionView(admin store.Administrator, s session.Session) map[string]any {
	return map[string]any{
		"name":        admin.Name,
		"permissions": admin.Permissions.Names(),
		"csrf_token":  s.CSRF,
		"expires_at":  s.Expires.UTC(),
	}
}

func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request, who caller) {
	pipeline.WriteJSON(w, http.StatusOK, sessionView(who.admin, who.session))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, who caller) {
	s.sessions.Revoke(who.token)
	s.audit.Record(audit.Event{Kind: "admin.logout", Method: r.Method, Path: r.URL.Path, Actor: who.admin.Name, Session: who.session.Reference})
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// handlePassword changes the caller's own password after verifying the
// current one, and ends all of the caller's sessions.
func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, who caller) {
	var body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decodeBody(w, r, maxAdminBody, &body) {
		return
	}
	if !validPassword(body.New) {
		adminError(w, http.StatusBadRequest, "bad_request", "new_password")
		return
	}
	now := time.Now()
	try, reason := s.throttle.begin(who.admin.Name, r, now)
	if reason != "" {
		s.refuse(w, r, http.StatusTooManyRequests, "too_many_attempts", reason, &who)
		return
	}
	if !s.acquireHashing() {
		try.abandoned()
		s.fail(w, r, &who, "busy", monitor.FailBusy, nil)
		return
	}
	verified := verifyPassword(who.admin.Password, body.Current)
	var passwordHash string
	if verified {
		passwordHash = hashPassword(body.New)
	}
	s.releaseHashing()
	if !verified {
		try.failed(now)
		s.refuse(w, r, http.StatusUnauthorized, "unauthenticated", "bad_credentials", &who)
		return
	}

	outcome, status := s.control.ChangePassword(r.Context(), who.admin, passwordHash)
	if status != http.StatusOK {
		try.abandoned()
		pipeline.WriteJSON(w, status, outcome)
		return
	}
	try.succeeded()
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
