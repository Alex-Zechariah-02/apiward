// Admin API status, policy and revision reads.

package gateway

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func (s *adminAPI) handleStatus(w http.ResponseWriter, r *http.Request, who caller) {
	state := s.control.State()
	status := map[string]any{
		"state":          state,
		"admission":      s.control.Admission(),
		"audit_failed":   s.audit.Failed(),
		"jwt_key_sha256": s.control.Verifier().Fingerprint(),
		"build":          currentBuild(),
	}
	if g := s.control.Current(); g != nil {
		status["revision"] = g.Revision
		status["generation"] = g.ID
		status["profile"] = g.Profile
		status["overrides"] = append([]int64{}, g.Overrides...)
		if !g.NotAfter.IsZero() {
			status["not_after"] = g.NotAfter.UTC()
		}
	}
	// The stored base, which differs from the served generation only while
	// the gateway is unavailable. A failed read is reported as such, so the
	// missing revisions are never read as "none".
	a, err := s.store.Load(r.Context())
	switch {
	case err != nil:
		s.logger.Error("reading authority for status", "error", err)
		status["stored_authority"] = "unreadable"
	case a.Mode == store.ModeNormal:
		status["confirmed"] = a.Confirmed
		if a.Provisional != 0 {
			status["provisional"] = a.Provisional
			status["deadline"] = a.Deadline.UTC()
		}
	}
	pipeline.WriteJSON(w, http.StatusOK, status)
}

// confirmedPolicy reads the confirmed base. It answers the request itself and
// returns false when no confirmed base is serving.
func (s *adminAPI) confirmedPolicy(w http.ResponseWriter, r *http.Request) (store.RevisionInfo, policy.Policy, bool) {
	a, err := s.store.Load(r.Context())
	if err != nil {
		s.logger.Error("reading authority", "error", err)
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return store.RevisionInfo{}, policy.Policy{}, false
	}
	if a.Mode != store.ModeNormal {
		adminError(w, http.StatusConflict, "no_confirmed_policy", "")
		return store.RevisionInfo{}, policy.Policy{}, false
	}
	revision, ok, err := s.store.Revision(r.Context(), a.Confirmed)
	if err == nil && !ok {
		err = fmt.Errorf("confirmed revision %d missing", a.Confirmed)
	}
	var p policy.Policy
	if err == nil {
		p, err = policy.DecodePolicy(revision.Document)
	}
	if err != nil {
		s.logger.Error("reading confirmed policy", "error", err)
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
		return store.RevisionInfo{}, policy.Policy{}, false
	}
	return revision, p, true
}

func (s *adminAPI) handlePolicy(w http.ResponseWriter, r *http.Request, who caller) {
	revision, _, ok := s.confirmedPolicy(w, r)
	if !ok {
		return
	}
	w.Header().Set("ETag", policyETag(revision.ID))
	pipeline.WriteJSON(w, http.StatusOK, revision)
}

func (s *adminAPI) handleRevisions(w http.ResponseWriter, r *http.Request, who caller) {
	after, limit, ok := page(w, r)
	if !ok {
		return
	}
	cursor, ok := numericCursor(w, after)
	if !ok {
		return
	}
	items, err := s.store.Revisions(r.Context(), cursor, limit)
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

func (s *adminAPI) handleRevision(w http.ResponseWriter, r *http.Request, who caller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	revision, found, err := s.store.Revision(r.Context(), id)
	switch {
	case err != nil:
		adminError(w, http.StatusServiceUnavailable, "unavailable", "")
	case !found:
		adminError(w, http.StatusNotFound, "not_found", "")
	default:
		pipeline.WriteJSON(w, http.StatusOK, revision)
	}
}

// writePolicyOutcome returns the receipt with the policy ETag the client
// needs next: the confirmed revision after a change, the current one after a
// stale precondition.
func (s *adminAPI) writePolicyOutcome(w http.ResponseWriter, r *http.Request, outcome Outcome, status int) {
	switch {
	case status == http.StatusOK && outcome.Provisional != 0 && outcome.Disposition == "":
		// An activation leaves the confirmed revision as it was.
		w.Header().Set("ETag", policyETag(outcome.RollbackTarget))
	case status == http.StatusOK && outcome.Revision != 0:
		w.Header().Set("ETag", policyETag(outcome.Revision))
	case status == http.StatusPreconditionFailed:
		if a, err := s.store.Load(r.Context()); err == nil && a.Mode == store.ModeNormal {
			w.Header().Set("ETag", policyETag(a.Confirmed))
		}
	}
	pipeline.WriteJSON(w, status, outcome)
}
