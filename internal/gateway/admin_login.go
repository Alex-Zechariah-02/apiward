// Admin API enrolment, sign-in, session and password handlers.

package gateway

import (
	"net/http"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// acquireHashing takes one of the bounded password-hashing slots.
func (s *adminAPI) acquireHashing() bool {
	select {
	case s.hashing <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *adminAPI) releaseHashing() { <-s.hashing }

func (s *adminAPI) handleEnrol(w http.ResponseWriter, r *http.Request) {
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
	if !store.IsAdminName(body.Name) || !validPassword(body.Password) {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	if s.store == nil {
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	now := time.Now()
	if reason := s.throttle.check(body.Name, now); reason != "" {
		s.refuse(w, r, http.StatusTooManyRequests, "too_many_attempts", reason, nil)
		return
	}
	e, found, err := s.store.Enrolment(r.Context(), session.Hash(body.Secret))
	if err != nil {
		s.logger.Error("reading enrolment", "error", err)
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	if !found || e.Name != body.Name || !now.Before(e.ExpiresAt) {
		s.throttle.failed(body.Name, false, now)
		s.refuse(w, r, http.StatusUnauthorized, "unauthenticated", "enrolment_invalid", nil)
		return
	}
	if !s.acquireHashing() {
		adminError(w, http.StatusServiceUnavailable, "busy", "")
		return
	}
	passwordHash := hashPassword(body.Password)
	s.releaseHashing()

	outcome, status := s.control.Enrol(r.Context(), e, passwordHash)
	if status != http.StatusOK {
		pipeline.WriteJSON(w, status, outcome)
		return
	}
	pipeline.WriteJSON(w, http.StatusCreated, map[string]any{"name": e.Name, "permissions": e.Permissions.Names()})
}

func (s *adminAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
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
	if reason := s.throttle.check(body.Name, now); reason != "" {
		s.refuse(w, r, http.StatusTooManyRequests, "too_many_attempts", reason, nil)
		return
	}
	admin, found, err := s.store.Administrator(r.Context(), body.Name)
	if err != nil {
		s.logger.Error("reading administrator", "error", err)
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
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
		adminError(w, http.StatusServiceUnavailable, "busy", "")
		return
	}
	verified := verifyPassword(encoded, body.Password) && active
	s.releaseHashing()
	if !verified {
		s.throttle.failed(body.Name, found, now)
		s.refuse(w, r, http.StatusUnauthorized, "unauthenticated", "bad_credentials", nil)
		return
	}
	s.throttle.succeeded(body.Name)

	token, created, err := s.sessions.Create(admin.Name, admin.Credential, now)
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "session_limit", "")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	s.audit.Record(audit.Event{Kind: "admin.authenticated", Method: r.Method, Path: r.URL.Path, Actor: admin.Name, Session: created.Reference})
	pipeline.WriteJSON(w, http.StatusCreated, sessionView(admin, created))
}

func sessionView(admin store.Administrator, s session.Session) map[string]any {
	return map[string]any{
		"name":        admin.Name,
		"permissions": admin.Permissions.Names(),
		"csrf_token":  s.CSRF,
		"expires_at":  s.Expires.UTC(),
	}
}

func (s *adminAPI) handleWhoAmI(w http.ResponseWriter, r *http.Request, who caller) {
	pipeline.WriteJSON(w, http.StatusOK, sessionView(who.admin, who.session))
}

func (s *adminAPI) handleLogout(w http.ResponseWriter, r *http.Request, who caller) {
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
func (s *adminAPI) handlePassword(w http.ResponseWriter, r *http.Request, who caller) {
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
	if reason := s.throttle.check(who.admin.Name, now); reason != "" {
		s.refuse(w, r, http.StatusTooManyRequests, "too_many_attempts", reason, &who)
		return
	}
	if !s.acquireHashing() {
		adminError(w, http.StatusServiceUnavailable, "busy", "")
		return
	}
	verified := verifyPassword(who.admin.Password, body.Current)
	var passwordHash string
	if verified {
		passwordHash = hashPassword(body.New)
	}
	s.releaseHashing()
	if !verified {
		s.throttle.failed(who.admin.Name, true, now)
		s.refuse(w, r, http.StatusUnauthorized, "unauthenticated", "bad_credentials", &who)
		return
	}

	outcome, status := s.control.ChangePassword(r.Context(), who.admin, passwordHash)
	if status != http.StatusOK {
		pipeline.WriteJSON(w, status, outcome)
		return
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
