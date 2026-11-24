// Admin API status, policy and revision reads.

package admin

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, who caller) {
	state := s.control.State()
	status := map[string]any{
		"state":            state,
		"admission":        s.control.Admission(),
		"audit_failed":     s.audit.Failed(),
		"audit_checkpoint": s.audit.Checkpoint(),
		"jwt_key_sha256":   s.control.Verifier().Fingerprint(),
		"build":            runningBuild(),
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

// handlePolicy answers the confirmed base as stored; the store checks its
// checksum when it reads it, so it is not decoded again here. A client that
// already holds it (If-None-Match naming its ETag) is answered 304.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request, who caller) {
	a, err := s.store.Load(r.Context())
	if err != nil {
		s.fail(w, r, &who, "unavailable", monitor.FailStore, err)
		return
	}
	if a.Mode != store.ModeNormal {
		adminError(w, http.StatusConflict, "no_confirmed_policy", "")
		return
	}
	tag := policyETag(a.Confirmed)
	w.Header().Set("ETag", tag)
	if matchesETag(r.Header.Values("If-None-Match"), tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	revision, ok, err := s.store.Revision(r.Context(), a.Confirmed)
	if err == nil && !ok {
		err = fmt.Errorf("confirmed revision %d missing", a.Confirmed)
	}
	if err != nil {
		s.fail(w, r, &who, "unavailable", monitor.FailStore, err)
		return
	}
	pipeline.WriteJSON(w, http.StatusOK, revision)
}

// matchesETag applies If-None-Match (RFC 9110 section 13.1.2): "*" or any
// listed tag equal to tag by weak comparison.
func matchesETag(fields []string, tag string) bool {
	for _, field := range fields {
		for item := range strings.SplitSeq(field, ",") {
			item = strings.TrimSpace(item)
			if item == "*" || strings.TrimPrefix(item, "W/") == strings.TrimPrefix(tag, "W/") {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleRevisions(w http.ResponseWriter, r *http.Request, who caller) {
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
		s.fail(w, r, &who, "unavailable", monitor.FailStore, err)
		return
	}
	result := list{Items: items}
	if len(items) == limit {
		result.Next = strconv.FormatInt(items[len(items)-1].ID, 10)
	}
	pipeline.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleRevision(w http.ResponseWriter, r *http.Request, who caller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	revision, found, err := s.store.Revision(r.Context(), id)
	switch {
	case err != nil:
		s.fail(w, r, &who, "unavailable", monitor.FailStore, err)
	case !found:
		adminError(w, http.StatusNotFound, "not_found", "")
	default:
		pipeline.WriteJSON(w, http.StatusOK, revision)
	}
}

// writePolicyOutcome returns the receipt with the policy ETag the client
// needs next: the confirmed revision after a change, the current one after a
// stale precondition.
func (s *Server) writePolicyOutcome(w http.ResponseWriter, r *http.Request, outcome controller.Outcome, status int) {
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
