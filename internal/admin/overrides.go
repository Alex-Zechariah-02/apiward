// Admin API temporary policy override handlers.

package admin

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// handleOverrides reports the overrides active now and the effective policy
// they belong to: the active base revision, the confirmed and provisional
// revisions and the serving generation, whose identity names the base and
// every applied override.
func (s *Server) handleOverrides(w http.ResponseWriter, r *http.Request, who caller) {
	a, err := s.store.Load(r.Context())
	if err != nil {
		s.logger.Error("reading authority", "error", err)
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	view := map[string]any{
		"revision":  a.Revision,
		"confirmed": a.Confirmed,
		"overrides": append([]store.Override{}, a.Overrides...),
	}
	if a.Provisional != 0 {
		view["provisional"] = a.Provisional
	}
	if g := s.control.Current(); g != nil {
		view["generation"] = g.ID
		view["generation_overrides"] = append([]int64{}, g.Overrides...)
	}
	w.Header().Set("ETag", policyETag(a.Confirmed))
	pipeline.WriteJSON(w, http.StatusOK, view)
}

func (s *Server) handleOverride(w http.ResponseWriter, r *http.Request, who caller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	o, found, err := s.store.Override(r.Context(), id)
	switch {
	case err != nil:
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
	case !found:
		adminError(w, http.StatusNotFound, "not_found", "")
	default:
		pipeline.WriteJSON(w, http.StatusOK, o)
	}
}

// handleOverrideHistory lists every override with its final disposition.
func (s *Server) handleOverrideHistory(w http.ResponseWriter, r *http.Request, who caller) {
	after, limit, ok := page(w, r)
	if !ok {
		return
	}
	cursor, ok := numericCursor(w, after)
	if !ok {
		return
	}
	items, err := s.store.Overrides(r.Context(), `WHERE id > ? ORDER BY id LIMIT ?`, cursor, limit)
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	result := list{Items: items}
	if len(items) == limit {
		result.Next = strconv.FormatInt(items[len(items)-1].ID, 10)
	}
	pipeline.WriteJSON(w, http.StatusOK, result)
}

// handleValidateOverride answers whether a proposed override would be
// created now. Nothing is created or recorded in the history.
func (s *Server) handleValidateOverride(w http.ResponseWriter, r *http.Request, who caller) {
	expected, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var request controller.OverrideRequest
	if !decodeBody(w, r, maxAdminBody, &request) {
		return
	}
	outcome, status := s.control.ValidateOverride(r.Context(), who.admin.Name, expected.Int64, request)
	pipeline.WriteJSON(w, status, outcome)
}

// handleCreateOverride creates a temporary override of the confirmed base.
// The If-Match precondition names the confirmed revision the administrator
// saw.
func (s *Server) handleCreateOverride(w http.ResponseWriter, r *http.Request, who caller) {
	expected, ok := ifMatch(w, r)
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	var request controller.OverrideRequest
	if !decodeBody(w, r, maxAdminBody, &request) {
		return
	}
	t := adminTransition(who, key, "tpo.create", "override", expected, request)
	outcome, status := s.control.CreateOverride(r.Context(), t, request)
	switch status {
	case http.StatusOK:
		status = http.StatusCreated
	case http.StatusPreconditionFailed:
		if a, err := s.store.Load(r.Context()); err == nil && a.Mode == store.ModeNormal {
			w.Header().Set("ETag", policyETag(a.Confirmed))
		}
	}
	pipeline.WriteJSON(w, status, outcome)
}

// handleRevokeOverride ends one active override.
func (s *Server) handleRevokeOverride(w http.ResponseWriter, r *http.Request, who caller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	t := adminTransition(who, key, "tpo.revoke", fmt.Sprintf("override %d", id), sql.NullInt64{}, nil)
	outcome, status := s.control.RevokeOverride(r.Context(), t, id)
	pipeline.WriteJSON(w, status, outcome)
}
