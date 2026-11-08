// Admin API candidate staging and confirmed activation handlers.

package gateway

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// candidateView marks every candidate as not active: staging never changes
// the enforced policy.
type candidateView struct {
	store.CandidateRecord
	Active   bool            `json:"active"`
	Document json.RawMessage `json:"document,omitempty"`
}

func (s *adminAPI) handleCandidates(w http.ResponseWriter, r *http.Request, who caller) {
	after, limit, ok := page(w, r)
	if !ok {
		return
	}
	cursor, ok := numericCursor(w, after)
	if !ok {
		return
	}
	records, err := s.store.Candidates(r.Context(), cursor, limit)
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	items := make([]candidateView, 0, len(records))
	for _, record := range records {
		items = append(items, candidateView{CandidateRecord: record})
	}
	result := list{Items: items}
	if len(records) == limit {
		result.Next = strconv.FormatInt(records[len(records)-1].ID, 10)
	}
	pipeline.WriteJSON(w, http.StatusOK, result)
}

func (s *adminAPI) handleCandidate(w http.ResponseWriter, r *http.Request, who caller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	record, found, err := s.store.Candidate(r.Context(), id)
	switch {
	case err != nil:
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
	case !found:
		adminError(w, http.StatusNotFound, "not_found", "")
	default:
		pipeline.WriteJSON(w, http.StatusOK, candidateView{CandidateRecord: record, Document: record.Document})
	}
}

// handlePostCandidate validates and stores a complete policy candidate. The
// If-Match precondition names the confirmed revision it was prepared against.
func (s *adminAPI) handlePostCandidate(w http.ResponseWriter, r *http.Request, who caller) {
	expected, ok := ifMatch(w, r)
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	var body struct {
		Policy json.RawMessage `json:"policy"`
	}
	if !decodeBody(w, r, maxCandidateBody, &body) {
		return
	}
	var compact bytes.Buffer
	if json.Compact(&compact, body.Policy) != nil {
		adminError(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	t := adminTransition(who, key, "candidate.create", "candidate", expected, compact.String())
	outcome, status := s.control.StageCandidate(r.Context(), t, body.Policy)
	if status != http.StatusOK {
		pipeline.WriteJSON(w, status, outcome)
		return
	}
	record, _, err := s.store.Candidate(r.Context(), outcome.Candidate)
	if err != nil {
		s.logger.Error("reading committed candidate", "error", err)
		outcome.Reason = "STORE_ERROR"
		pipeline.WriteJSON(w, http.StatusServiceUnavailable, outcome)
		return
	}
	pipeline.WriteJSON(w, http.StatusCreated, map[string]any{"receipt": outcome, "candidate": candidateView{CandidateRecord: record}})
}

func (s *adminAPI) handleWithdrawCandidate(w http.ResponseWriter, r *http.Request, who caller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	t := adminTransition(who, key, "candidate.withdraw", fmt.Sprintf("candidate %d", id), sql.NullInt64{}, nil)
	outcome, status := s.control.WithdrawCandidate(r.Context(), t, id)
	pipeline.WriteJSON(w, status, outcome)
}

// handleEstablish confirms a deny-all candidate as the first base (genesis)
// or the base that ends a recovery. The checksum shows the administrator
// confirmed the exact document.
func (s *adminAPI) handleEstablish(kind string) adminHandler {
	return func(w http.ResponseWriter, r *http.Request, who caller) {
		var body struct {
			Candidate int64  `json:"candidate"`
			Checksum  string `json:"checksum"`
		}
		if !decodeBody(w, r, maxAdminBody, &body) {
			return
		}
		outcome, status := s.control.EstablishBase(r.Context(), kind, who.admin.Name, body.Candidate, body.Checksum)
		pipeline.WriteJSON(w, status, outcome)
	}
}

// handleActivate makes a staged candidate the provisional active base. The
// If-Match precondition names the confirmed revision that becomes the
// rollback target; the checksum shows the administrator chose the exact
// document.
func (s *adminAPI) handleActivate(w http.ResponseWriter, r *http.Request, who caller) {
	expected, ok := ifMatch(w, r)
	if !ok {
		return
	}
	key, ok := idempotencyKey(w, r)
	if !ok {
		return
	}
	var body struct {
		Candidate            int64  `json:"candidate"`
		Checksum             string `json:"checksum"`
		ConfirmWithinSeconds int64  `json:"confirm_within_seconds"`
	}
	if !decodeBody(w, r, maxAdminBody, &body) {
		return
	}
	t := adminTransition(who, key, "cpa.activate", fmt.Sprintf("candidate %d", body.Candidate), expected, body)
	outcome, status := s.control.Activate(r.Context(), t, body.Candidate, body.Checksum, body.ConfirmWithinSeconds)
	s.writePolicyOutcome(w, r, outcome, status)
}

// handleResolve confirms or rolls back the provisional revision named in the
// body.
func (s *adminAPI) handleResolve(kind, disposition string) adminHandler {
	return func(w http.ResponseWriter, r *http.Request, who caller) {
		expected, ok := ifMatch(w, r)
		if !ok {
			return
		}
		key, ok := idempotencyKey(w, r)
		if !ok {
			return
		}
		var body struct {
			Revision int64 `json:"revision"`
		}
		if !decodeBody(w, r, maxAdminBody, &body) {
			return
		}
		t := adminTransition(who, key, kind, fmt.Sprintf("revision %d", body.Revision), expected, body)
		outcome, status := s.control.Resolve(r.Context(), t, body.Revision, disposition)
		s.writePolicyOutcome(w, r, outcome, status)
	}
}

// handleProvisional reports the current provisional base: its activation
// record, the generation serving it and every control target it changes
// relative to its rollback target.
func (s *adminAPI) handleProvisional(w http.ResponseWriter, r *http.Request, who caller) {
	ctx := r.Context()
	a, err := s.store.Load(ctx)
	if err != nil {
		s.logger.Error("reading authority", "error", err)
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	w.Header().Set("ETag", policyETag(a.Confirmed))
	if a.Provisional == 0 {
		adminError(w, http.StatusNotFound, "no_provisional", "")
		return
	}
	record, found, err := s.store.Activation(ctx, "revision", a.Provisional)
	if err == nil && !found {
		err = fmt.Errorf("activation of revision %d missing", a.Provisional)
	}
	var before, after policy.Policy
	if err == nil {
		before, err = s.store.Policy(ctx, a.Confirmed)
	}
	if err == nil {
		after, err = s.store.Policy(ctx, a.Provisional)
	}
	if err != nil {
		s.logger.Error("reading the provisional base", "error", err)
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	view := map[string]any{"activation": record, "changes": compile.PolicyChanges(before, after)}
	if g := s.control.Current(); g != nil && g.Revision == a.Provisional {
		view["generation"] = g.ID
	}
	pipeline.WriteJSON(w, http.StatusOK, view)
}

// handleActivations lists every provisional base with its final disposition.
func (s *adminAPI) handleActivations(w http.ResponseWriter, r *http.Request, who caller) {
	after, limit, ok := page(w, r)
	if !ok {
		return
	}
	cursor, ok := numericCursor(w, after)
	if !ok {
		return
	}
	items, err := s.store.Activations(r.Context(), cursor, limit)
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	result := list{Items: items}
	if len(items) == limit {
		result.Next = strconv.FormatInt(items[len(items)-1].Revision, 10)
	}
	pipeline.WriteJSON(w, http.StatusOK, result)
}
