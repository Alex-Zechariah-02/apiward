// Access questions: whether a described request would pass the checks that
// need neither live traffic nor a real body, answered by the same matching
// and permission code as real requests, in the request handler's order.

package compile

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// Bounds of the host and headers a question may give: a host name with a
// port, and as many headers as conditions allow, each as long as one.
const (
	maxQuestionHost    = 253 + len(":65535")
	maxQuestionHeaders = 2 * policy.MaxWhenHeaders
	maxQuestionValue   = 256
)

// questionMethods are the methods a question may ask about.
var questionMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

// Question is a checked request description. Only NewQuestion makes one,
// so every question has passed the request handler's own input checks.
type Question struct {
	method  string
	path    string
	inbound Inbound
	roles   []string
}

// NewQuestion checks a request description: the method, the path in the
// form the handler accepts, the roles standing for a verified token's, and
// the host and headers conditions select by. field names the refused input.
func NewQuestion(method, path, host string, headers map[string]string, roles []string) (q Question, field string) {
	if !slices.Contains(questionMethods, method) {
		return q, "method"
	}
	canonical, ok := checkedPath(path)
	if !ok {
		return q, "path"
	}
	if len(roles) > policy.MaxTokenRoles || slices.ContainsFunc(roles, func(role string) bool { return role == "" || len(role) > policy.MaxIDLength }) {
		return q, "roles"
	}
	if len(host) > maxQuestionHost {
		return q, "host"
	}
	if len(headers) > maxQuestionHeaders {
		return q, "headers"
	}
	header := http.Header{}
	for name, value := range headers {
		if name == "" || len(name) > policy.MaxHeaderName || len(value) > maxQuestionValue {
			return q, "headers"
		}
		header.Set(name, value)
	}
	return Question{method: method, path: canonical, inbound: Inbound{Host: host, Header: header}, roles: roles}, ""
}

// checkedPath applies the request handler's canonical-path check to a path
// given as text, so the same targets are refused before routing.
func checkedPath(text string) (string, bool) {
	if !strings.HasPrefix(text, "/") || len(text) > policy.MaxTargetLength || strings.ContainsAny(text, "?#") {
		return "", false
	}
	parsed, err := url.ParseRequestURI(text)
	if err != nil {
		return "", false
	}
	return CanonicalPath(&http.Request{URL: parsed})
}

// Answer is a question's decision. Check and Code name the refusing check
// (route, access, blocked, role, forward) and its error code; both are empty
// when the request would be allowed.
type Answer struct {
	Allowed   bool
	Check     string
	Code      string
	Operation string // empty when no operation matched
	API       string
	Public    bool
	Forwarded string // the path an allowed request reaches its upstream with
	Roles     []string
	Ignored   []string
	// NotChecked lists the checks this answer could not make.
	NotChecked []string
}

// Decide answers q with g. blocked reports whether the account asked about
// is on the blocked list; it is asked only for a protected operation.
func (g *Generation) Decide(q Question, blocked func() bool) Answer {
	answer := Answer{Roles: []string{}, Ignored: []string{}, NotChecked: []string{"rate", "body"}}
	refuse := func(check, code string) Answer {
		answer.Check, answer.Code = check, code
		return answer
	}
	target, rule := g.Match(q.path, q.method, q.inbound)
	if target == nil {
		return refuse("route", "not_found")
	}
	if rule == nil {
		return refuse("route", "method_not_allowed")
	}
	answer.Operation, answer.API, answer.Public = rule.Operation(), rule.API(), rule.Public()
	if !rule.Permitted() {
		return refuse("access", "forbidden")
	}
	if !rule.Public() {
		// A real request also needs a valid token from the trusted issuer;
		// the roles asked about stand for its verified roles.
		answer.NotChecked = []string{"token", "rate", "body"}
		roles, ignored, reason := g.Authorise(q.roles, rule)
		answer.Roles, answer.Ignored = nonNil(roles), nonNil(ignored)
		if blocked() {
			return refuse("blocked", "account_blocked")
		}
		if reason != "" {
			return refuse("role", "forbidden")
		}
	}
	destination, ok := rule.Destination(q.path)
	if !ok {
		return refuse("forward", "path_not_canonical")
	}
	answer.Allowed, answer.Forwarded = true, destination.Path()
	return answer
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
