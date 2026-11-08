// Admin API Access Checker: a request asked about against the generation in
// force or a stored draft, decided by compile.Decide.

package admin

import (
	"net/http"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// accessCheck asks whether a request would pass the checks that do not depend
// on live traffic or a real body: routing, the endpoint's access, the blocked
// accounts and the role permissions. Roles stand for a verified token's roles;
// Host and Headers stand for the request's, which conditions select by.
type accessCheck struct {
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Host      string            `json:"host"`
	Headers   map[string]string `json:"headers"`
	Roles     []string          `json:"roles"`
	Subject   *string           `json:"subject"`
	Candidate *int64            `json:"candidate"`
}

type accessAnswer struct {
	Decision  string  `json:"decision"`
	Code      *string `json:"code"`
	Check     *string `json:"check"`
	Operation *string `json:"operation"`
	API       *string `json:"api"`
	Public    bool    `json:"public"`
	// ForwardedPath is the path an allowed request reaches its upstream
	// with; null when the request is refused.
	ForwardedPath *string  `json:"forwarded_path"`
	Roles         []string `json:"roles"`
	IgnoredRoles  []string `json:"ignored_roles"`
	Generation    string   `json:"generation"`
	Candidate     *int64   `json:"candidate"`
	NotChecked    []string `json:"not_checked"`
}

// handleAccessCheck answers with the generation in force, or with a stored
// draft compiled with the active overrides, through the same matching and
// permission code as real requests. It changes nothing and is no second
// evaluator: every decision below is the request handler's own function.
func (s *Server) handleAccessCheck(w http.ResponseWriter, r *http.Request, who caller) {
	var check accessCheck
	if !decodeBody(w, r, maxAdminBody, &check) {
		return
	}
	question, field := compile.NewQuestion(check.Method, check.Path, check.Host, check.Headers, check.Roles)
	if field != "" {
		adminError(w, http.StatusBadRequest, "bad_request", field)
		return
	}
	if check.Subject != nil && (*check.Subject == "" || len(*check.Subject) > policy.MaxIDLength) {
		adminError(w, http.StatusBadRequest, "bad_request", "subject")
		return
	}

	g := s.control.Current()
	if check.Candidate != nil {
		var ok bool
		if _, g, ok = s.candidateGeneration(w, r, *check.Candidate); !ok {
			return
		}
	} else if g == nil || g.Expired(compile.TrustedNow()) {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	blocked := s.control.Blocked()
	if blocked == nil {
		adminError(w, http.StatusServiceUnavailable, "gateway_unavailable", "")
		return
	}
	decision := g.Decide(question, func() bool {
		if check.Subject == nil {
			return false
		}
		_, found := (*blocked)[*check.Subject]
		return found
	})
	pipeline.WriteJSON(w, http.StatusOK, newAccessAnswer(decision, g.ID, check.Candidate))
}

// newAccessAnswer puts a decision in the Admin API's answer form, where an
// absent value is null.
func newAccessAnswer(d compile.Answer, generation string, candidate *int64) accessAnswer {
	answer := accessAnswer{Decision: "allowed", Generation: generation, Candidate: candidate, Public: d.Public,
		Roles: d.Roles, IgnoredRoles: d.Ignored, NotChecked: d.NotChecked}
	if d.Operation != "" {
		answer.Operation, answer.API = &d.Operation, &d.API
	}
	if !d.Allowed {
		answer.Decision, answer.Check, answer.Code = "refused", &d.Check, &d.Code
		return answer
	}
	answer.ForwardedPath = &d.Forwarded
	return answer
}
