// Canonical paths, route matching and role authorisation.

package compile

import (
	"net/http"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// parseTarget returns the match prefix for "/a/*" targets, or "" for exact
// targets. Targets must already be canonical.
func parseTarget(pattern string) (string, bool) {
	if len(pattern) > policy.MaxTargetLength {
		return "", false
	}
	path, isPrefix := strings.CutSuffix(pattern, "/*")
	if isPrefix {
		path += "/"
	}
	if !IsCanonical(path) || strings.Contains(path, "*") {
		return "", false
	}
	if isPrefix {
		return path, true
	}
	return "", true
}

// CanonicalPath returns the single path interpretation used for matching and
// forwarding. Any encoding whose meaning could differ between the gateway and
// an upstream is rejected rather than normalised.
func CanonicalPath(r *http.Request) (string, bool) {
	if bannedEscape(r.URL.EscapedPath()) {
		return "", false
	}
	path := r.URL.Path
	if !IsCanonical(path) {
		return "", false
	}
	return path, true
}

// bannedEscape reports an escape of '/', '\\', '.' or NUL in either
// letter case.
func bannedEscape(escaped string) bool {
	for i := strings.IndexByte(escaped, '%'); i >= 0 && i+2 < len(escaped); {
		switch escaped[i+1] {
		case '0':
			if escaped[i+2] == '0' {
				return true
			}
		case '2':
			if c := escaped[i+2] | 0x20; c == 'f' || c == 'e' {
				return true
			}
		case '5':
			if escaped[i+2]|0x20 == 'c' {
				return true
			}
		}
		next := strings.IndexByte(escaped[i+1:], '%')
		if next < 0 {
			return false
		}
		i += 1 + next
	}
	return false
}

// IsCanonical reports a path of printable ASCII without '\\' or '%' whose
// segments are neither "." nor "..", and empty only as a trailing slash.
func IsCanonical(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	start := 1 // the current segment's first byte
	for i := 1; i <= len(path); i++ {
		if i < len(path) {
			c := path[i]
			if c < 0x21 || c > 0x7e || c == '\\' || c == '%' {
				return false
			}
			if c != '/' {
				continue
			}
		}
		segment := path[start:i]
		if segment == "." || segment == ".." || segment == "" && i != len(path) {
			return false
		}
		start = i + 1
	}
	return true
}

// Match selects the most specific target for a canonical path, then the
// method on that target only, then among that method's operations the one
// with the most conditions the request meets, else the unconditioned one. A
// less specific target is never consulted for a missing method. When the
// method has only conditioned operations and none holds, no target matches.
func (g *Generation) Match(path, method string, in Inbound) (*target, *Rule) {
	t := g.lookup(path)
	if t == nil {
		return nil, nil
	}
	rule := t.match(method, in)
	if rule == nil && len(t.variants[method]) > 0 {
		return nil, nil
	}
	return t, rule
}

// match selects the method's operation on t as Match does; nil when none.
func (t *target) match(method string, in Inbound) *Rule {
	if variants := t.variants[method]; len(variants) > 0 {
		host := requestHost(in.Host)
		for _, v := range variants {
			if v.when.holds(host, in.Header) {
				return v
			}
		}
	}
	return t.methods[method]
}

// Conditioned reports whether the method on the path's target has
// conditioned operations, so the operation depends on host and headers.
func (g *Generation) Conditioned(path, method string) bool {
	t := g.lookup(path)
	return t != nil && len(t.variants[method]) > 0
}

// Preflight returns the rule a CORS preflight's requested method selects on
// the path, as Match would for the actual request, and the rule whose API
// settings (address allow list, preflight rate) apply: the selected rule, or
// when none is selected the target's first operation of an API with browser
// access. api is nil, and the gateway does not answer the preflight, when
// the path's target has no such operation.
func (g *Generation) Preflight(path, method string, in Inbound) (rule, api *Rule) {
	t := g.lookup(path)
	if t == nil || t.cors == nil {
		return nil, nil
	}
	rule = t.match(method, in)
	if rule == nil {
		return nil, t.cors
	}
	return rule, rule
}

// lookup returns the most specific target for a canonical path.
func (g *Generation) lookup(path string) *target {
	if len(path) <= g.longest {
		if t := g.exact[path]; t != nil {
			return t
		}
	}
	for _, candidate := range g.prefixes {
		rest, ok := strings.CutPrefix(path, candidate.prefix)
		if ok && rest != "" {
			return candidate
		}
	}
	return nil
}

// Authorise retains only declared roles from already verified claims. Unknown
// roles are returned for audit; a subject name never creates a permission.
func (g *Generation) Authorise(asserted []string, r *Rule) (roles, ignored []string, reason string) {
	allowed := false
	for _, role := range asserted {
		// A permitted role is always declared, so one lookup settles it.
		permitted := r.roles[role]
		switch {
		case permitted || g.roles[role]:
			if roles == nil {
				roles = make([]string, 0, len(asserted))
			}
			roles = append(roles, role)
			allowed = allowed || permitted
		default:
			ignored = append(ignored, role)
		}
	}
	if !allowed {
		reason = "no_permit"
	}
	return
}
