// The reference evaluator: one decision order over routes reduced to shared primitives.

package probe

import (
	"github.com/Alex-Zechariah-02/apiward/internal/semantics"
)

// Decide is the reference decision for one request: the route is the
// first in the source's precedence order that takes the path and method
// and whose conditions hold, replaced by a later one on the same path with
// more conditions holding; then its allow list, access, sign-in, roles, body size
// and body schema decide. The rate limit is judged over a burst (Burst),
// not here; a preflight is decided by its browser access (preflight). It
// returns the chosen route, nil when none was chosen.
func Decide(routes []semantics.Route, r Request) (Class, *semantics.Route) {
	if r.IsPreflight() {
		if class, route, handled := preflight(routes, r); handled {
			return class, route
		}
	}
	route, class := choose(routes, r)
	if route == nil {
		return class, nil
	}
	switch {
	case !route.Admits(r.Client), route.Deny:
		return Authz, route
	case route.Identity != nil && !route.Identity.Authenticates(r.Token):
		return Authn, route
	case route.Identity != nil && route.Roles != nil && !route.Roles.Allows(route.Held(r.Roles)):
		return Authz, route
	case r.Body == Oversized && route.MaxBytes > 0 && r.Size > route.MaxBytes:
		return Size, route
	case r.Body == Invalid && route.Schema:
		return Validation, route
	}
	return Forwarded, route
}

// choose returns the route taking the request, or the class of the miss:
// not_found when no route takes the path or none of its conditions hold,
// method when routes take the path but not the method.
func choose(routes []semantics.Route, r Request) (*semantics.Route, Class) {
	var chosen *semantics.Route
	path, method := false, false
	for i := range routes {
		route := &routes[i]
		if !route.Path.Matches(r.Path) {
			continue
		}
		path = true
		if route.Method != r.Method {
			continue
		}
		method = true
		if route.Holds(r.Host, r.Header) && (chosen == nil || route.Path == chosen.Path && route.Rank() > chosen.Rank()) {
			chosen = route
		}
	}
	switch {
	case chosen != nil:
		return chosen, ""
	case path && !method:
		return nil, Method
	}
	return nil, NotFound
}

// Burst is the reference decision for the last of count+1 requests sent
// at the given Unix milliseconds to a route: rate when the route's limiter
// refuses any of them, else forwarded.
func Burst(route *semantics.Route, times []int64) Class {
	if route == nil || route.Rate == nil {
		return Forwarded
	}
	limiter := route.Rate.Limiter()
	class := Forwarded
	for _, now := range times {
		if !limiter.Admit(now) {
			class = Rate
		}
	}
	return class
}
