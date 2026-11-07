// Route primitives: what a source gateway decides for one route and method, as reference tests evaluate it.

package semantics

import (
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Route is one route and method of a source gateway, reduced to the
// primitives that decide a request. A reader lists its routes in the
// source's precedence order.
type Route struct {
	Operation string // the exchange operation the route became
	Method    string // upper case
	Path      PathRule
	Hosts     []string // lower-case names or *.domain; empty: any host
	Headers   []Header // each must hold
	Deny      bool     // every caller refused
	Allow     []netip.Prefix
	Identity  *Identity // nil: public
	Roles     *Roles    // nil: every signed-in caller
	Groups    []string  // what a signed-in caller holds when Roles reads gateway groups
	MaxBytes  int64     // 0: no body limit
	Schema    bool      // bodies are checked against the operation's schema
	Rate      *Rate     // nil: no limit
	CORS      *CORS     // nil: no browser access
}

// CORS is a route's browser access, as a browser checks a preflight's
// answer. Requested: the gateway answers a preflight for the route the
// requested method selects; otherwise the preflight's own OPTIONS must
// select the route, as in Kong.
type CORS struct {
	Origins   []string // exact origins or *; whole-match regular expressions when Patterns
	Patterns  bool
	Methods   []string
	Headers   []string
	AnyHeader bool // every requested header is allowed
	Requested bool
}

// Allows is the decision rule of a preflight: the origin, the requested
// method and every requested header are allowed.
func (c CORS) Allows(origin, method string, headers []string) bool {
	matches := func(allowed string) bool {
		if allowed == "*" || !c.Patterns {
			return allowed == "*" || allowed == origin
		}
		pattern, err := regexp.Compile(`^(?:` + allowed + `)$`)
		return err == nil && pattern.MatchString(origin)
	}
	if !slices.ContainsFunc(c.Origins, matches) || !slices.Contains(c.Methods, method) {
		return false
	}
	return c.AnyHeader || !slices.ContainsFunc(headers, func(h string) bool {
		return !slices.ContainsFunc(c.Headers, func(allowed string) bool { return strings.EqualFold(allowed, h) })
	})
}

// Header is one header condition: the header is sent once with Value;
// Fold compares the value without regard to case.
type Header struct {
	Name, Value string
	Fold        bool
}

// Rank is how many conditions select the route: its host list counts once,
// each header once. The route with the most conditions holding wins.
func (r Route) Rank() int {
	rank := len(r.Headers)
	if len(r.Hosts) > 0 {
		rank++
	}
	return rank
}

// Holds is the decision rule of the conditions: the host (lower case, no
// port) is one of Hosts, where *.domain takes one or more labels before
// domain, and every header condition holds.
func (r Route) Holds(host string, headers http.Header) bool {
	if len(r.Hosts) > 0 && !hostIn(host, r.Hosts) {
		return false
	}
	for _, h := range r.Headers {
		values := headers.Values(h.Name)
		if len(values) != 1 || !(values[0] == h.Value || h.Fold && strings.EqualFold(values[0], h.Value)) {
			return false
		}
	}
	return true
}

func hostIn(host string, hosts []string) bool {
	for _, pattern := range hosts {
		domain, wildcard := strings.CutPrefix(pattern, "*")
		if host == pattern || wildcard && len(host) > len(domain) && strings.HasSuffix(host, domain) {
			return true
		}
	}
	return false
}

// Admits reports whether a client address passes the route's allow list.
func (r Route) Admits(client netip.Addr) bool {
	if r.Allow == nil {
		return true
	}
	for _, prefix := range r.Allow {
		if prefix.Contains(client.Unmap()) {
			return true
		}
	}
	return false
}

// Held returns the roles a signed-in caller holds at the source: the
// token's roles, or the groups stored at the source gateway.
func (r Route) Held(token []string) []string {
	if r.Roles != nil && r.Roles.Source == GatewayGroups {
		return r.Groups
	}
	return token
}
