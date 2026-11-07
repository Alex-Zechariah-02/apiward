// Source routes: the Kong route behind each imported operation, reduced to shared primitives for reference tests.

package kong

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/Alex-Zechariah-02/apiward/internal/semantics"
)

// sourceRoute is what Kong decides for one route and method: its path
// rule, conditions, sign-in with the checks Kong makes, the acl over the
// signed-in consumer's groups, and Kong's own body limit and calendar rate.
func (r *reader) sourceRoute(operation, method string, rule semantics.PathRule, c *controls) semantics.Route {
	route := semantics.Route{Operation: operation, Method: method, Path: rule, Deny: c.deny,
		Groups: r.groups, MaxBytes: c.sourceBytes, Rate: c.sourceRate, Hosts: texts(c.when["hosts"])}
	switch {
	case c.auth: // an anonymous consumer callers reach makes the route public
		route.Identity = c.identity
	case c.deny: // Kong's acl answers 401 when no plugin signs callers in
		route.Deny, route.Identity = false, &semantics.Identity{Scheme: semantics.Absent}
	}
	if c.roles != nil {
		route.Roles = &semantics.Roles{Source: semantics.GatewayGroups, Rule: semantics.AllowList, Values: c.roles}
	}
	for _, entry := range c.allow {
		if prefix, err := netip.ParsePrefix(entry); err == nil { // canonical ranges, checked by the ip-restriction row
			route.Allow = append(route.Allow, prefix)
		}
	}
	if c.cors != nil && c.cors.plugin.config["preflight_continue"] != true { // else Kong forwards preflights
		cfg := c.cors.plugin.config
		route.CORS = &semantics.CORS{Origins: texts(cfg["origins"]), Patterns: true, Methods: texts(cfg["methods"]),
			Headers: texts(cfg["headers"]), AnyHeader: len(texts(cfg["headers"])) == 0}
		if len(route.CORS.Origins) == 0 {
			route.CORS.Origins = []string{"*"}
		}
		if len(route.CORS.Methods) == 0 {
			route.CORS.Methods = corsMethods
		}
	}
	for _, h := range list(c.when["headers"]) {
		// Kong compares header values without regard to case.
		route.Headers = append(route.Headers, semantics.Header{Name: text(object(h)["name"]), Value: text(object(h)["value"]), Fold: true})
	}
	return route
}

// kongOrder sorts routes as Kong's router tries them: more conditions
// first, then longer paths. Overlapping regular-expression and plain paths
// of equal length are not ordered by regex_priority here.
func kongOrder(routes []semantics.Route) []semantics.Route {
	slices.SortStableFunc(routes, func(a, b semantics.Route) int {
		return cmp.Or(cmp.Compare(b.Rank(), a.Rank()), cmp.Compare(len(b.Path.Value), len(a.Path.Value)))
	})
	return routes
}
