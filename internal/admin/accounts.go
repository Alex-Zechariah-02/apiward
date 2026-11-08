// Admin API trust keys, blocked accounts and administrators.

package admin

import (
	"database/sql"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// handleKeys lists the trusted keys with how many tokens each verified since
// the gateway started and when it last did; counts only, no key material.
func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request, who caller) {
	type keyReport struct {
		pipeline.KeyInfo
		Verified       uint64     `json:"verified"`
		LastVerifiedAt *time.Time `json:"last_verified_at"`
	}
	v := s.control.Verifier()
	items := make([]keyReport, 0, len(v.Keys()))
	for _, info := range v.Keys() {
		report := keyReport{KeyInfo: info}
		if use := v.Use(info.Kid); use != nil {
			report.Verified = use.Count()
			if last := use.Last(); last != 0 {
				at := time.Unix(0, last).UTC()
				report.LastVerifiedAt = &at
			}
		}
		items = append(items, report)
	}
	pipeline.WriteJSON(w, http.StatusOK, list{Items: items})
}

func noRequestBody(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return false
	}
	return true
}

func (s *Server) handleReloadKeys(w http.ResponseWriter, r *http.Request, who caller) {
	if !noRequestBody(w, r) {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	t := adminTransition(who, key, "keys.reload", "keys", sql.NullInt64{}, nil)
	body, status := s.control.ReloadKeys(r.Context(), t)
	pipeline.WriteJSON(w, status, body)
}

func (s *Server) handleBlockedAccounts(w http.ResponseWriter, r *http.Request, who caller) {
	current := s.control.Blocked()
	if current == nil {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	items := slices.Collect(maps.Values(*current))
	if items == nil {
		items = []store.BlockedAccount{}
	}
	slices.SortFunc(items, func(a, b store.BlockedAccount) int { return strings.Compare(a.Subject, b.Subject) })
	pipeline.WriteJSON(w, http.StatusOK, list{Items: items})
}

func (s *Server) handleBlockAccount(w http.ResponseWriter, r *http.Request, who caller) {
	subject := r.PathValue("subject")
	if !policy.IsSubjectID(subject) {
		adminError(w, http.StatusBadRequest, "bad_request", "subject")
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if !decodeBody(w, r, maxAdminBody, &request) {
		return
	}
	if !store.ValidBlockReason(request.Reason) {
		adminError(w, http.StatusBadRequest, "bad_request", "reason")
		return
	}
	t := adminTransition(who, key, "account.block", subject, sql.NullInt64{}, request)
	body, status := s.control.Block(r.Context(), t, request.Reason)
	pipeline.WriteJSON(w, status, body)
}

func (s *Server) handleUnblockAccount(w http.ResponseWriter, r *http.Request, who caller) {
	subject := r.PathValue("subject")
	if !policy.IsSubjectID(subject) {
		adminError(w, http.StatusBadRequest, "bad_request", "subject")
		return
	}
	if !noRequestBody(w, r) {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	t := adminTransition(who, key, "account.unblock", subject, sql.NullInt64{}, nil)
	body, status := s.control.Unblock(r.Context(), t)
	pipeline.WriteJSON(w, status, body)
}

func (s *Server) handleAdministrators(w http.ResponseWriter, r *http.Request, who caller) {
	entries, err := s.store.Administrators(r.Context())
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	type view struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
		Status      string   `json:"status"`
	}
	items := []view{}
	for _, entry := range entries {
		items = append(items, view{Name: entry.Name, Permissions: entry.Permissions.Names(), Status: entry.Status})
	}
	pipeline.WriteJSON(w, http.StatusOK, list{Items: items})
}
