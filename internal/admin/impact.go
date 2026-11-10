// Admin API impact estimate for a candidate.

package admin

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// candidateGeneration compiles a stored draft with the active overrides,
// as an activation would, beside the generation in force. It settles no
// deadline and publishes nothing. On failure it has answered the request.
func (s *Server) candidateGeneration(w http.ResponseWriter, r *http.Request, id int64) (current, candidate *compile.Generation, ok bool) {
	stored, found, err := s.store.Candidate(r.Context(), id)
	if err != nil {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return nil, nil, false
	}
	if !found {
		adminError(w, http.StatusNotFound, "not_found", "")
		return nil, nil, false
	}
	policy, err := policy.DecodePolicy(stored.Document, s.config.Limits)
	if err != nil {
		adminError(w, http.StatusUnprocessableEntity, "candidate_invalid", "")
		return nil, nil, false
	}
	// Both use the same complete-policy resolver as an activation, including
	// independent temporary controls.
	current, authority, err := s.control.Capture(r.Context())
	if current == nil || err != nil {
		adminError(w, 503, "gateway_unavailable", "")
		return nil, nil, false
	}
	candidate, err = controller.CandidateGeneration(s.control.Network(), policy, stored.Parent, authority.Overrides, s.config.Limits)
	if err != nil {
		adminError(w, http.StatusUnprocessableEntity, "candidate_invalid", "")
		return nil, nil, false
	}
	return current, candidate, true
}

func (s *Server) handleImpact(w http.ResponseWriter, r *http.Request, who caller) {
	if !noRequestBody(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	before, after, ok := s.candidateGeneration(w, r, id)
	if !ok {
		return
	}
	type flip struct {
		Operation string   `json:"operation"`
		Subject   *string  `json:"subject"`
		Roles     []string `json:"roles"`
		Before    string   `json:"before"`
		After     string   `json:"after"`
		AfterCode *string  `json:"after_code"`
		Count     int      `json:"count"`
	}
	events := s.observations.Snapshot()
	groups := map[string]*flip{}
	unknown := 0
	for _, event := range events {
		old, _, oldOperation, oldKnown := monitor.PreviewDecision(before, event)
		current, code, operation, currentKnown := monitor.PreviewDecision(after, event)
		if !oldKnown || !currentKnown {
			unknown++
			continue
		}
		if old == current {
			continue
		}
		if operation == "" {
			operation = oldOperation
		}
		value := flip{Operation: operation, Subject: event.Subject, Roles: event.ClaimedRoles(), Before: old, After: current, AfterCode: monitor.OptionalString(code)}
		key, _ := json.Marshal(value)
		if groups[string(key)] == nil {
			groups[string(key)] = &value
		}
		groups[string(key)].Count++
	}
	flips := []flip{}
	for _, key := range slices.Sorted(maps.Keys(groups)) {
		flips = append(flips, *groups[key])
	}
	now := time.Now().UTC()
	from := now
	if len(events) > 0 {
		from = events[len(events)-1].Time
	}
	type window struct {
		From            time.Time `json:"from"`
		To              time.Time `json:"to"`
		Requests        int       `json:"requests"`
		Previewed       int       `json:"previewed"`
		IdentityUnknown int       `json:"identity_unknown"`
	}
	notPreviewed := []string{"rate", "body"}
	if unknown > 0 {
		notPreviewed = append(notPreviewed, "unobserved_identity")
	}
	pipeline.WriteJSON(w, http.StatusOK, struct {
		Window       window   `json:"window"`
		Flips        []flip   `json:"flips"`
		NotPreviewed []string `json:"not_previewed"`
	}{window{from, now, len(events), len(events) - unknown, unknown}, flips, notPreviewed})
}
