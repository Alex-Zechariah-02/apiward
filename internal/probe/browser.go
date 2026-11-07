// Browser access: preflight probes, the reference decision of a preflight, and the browser's check of an answer.

package probe

import (
	"net/http"
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/semantics"
)

// Preflight request headers (Fetch standard).
const (
	headerOrigin  = "Origin"
	headerMethod  = "Access-Control-Request-Method"
	headerHeaders = "Access-Control-Request-Headers"
)

// Origins and a header no browser access lists (RFC 2606).
const (
	anyOrigin      = "https://probe.example"
	unlistedOrigin = "https://unlisted.invalid"
	unlistedHeader = "X-Unlisted-Probe"
)

// safelisted are the methods a browser sends without checking Allow-Methods.
var safelisted = []string{"GET", "HEAD", "POST"}

// IsPreflight reports whether the request is a CORS preflight.
func (r Request) IsPreflight() bool {
	return r.Method == http.MethodOptions && r.Header.Get(headerOrigin) != "" && r.Header.Get(headerMethod) != ""
}

// preflights probes the operation's browser access: a listed origin with
// the operation's method, an unlisted origin, an unlisted method and an
// unlisted header. Operations of OPTIONS and HEAD are not probed.
func (g *generator) preflights(o Operation, base Probe) {
	c := o.Route.CORS
	if c == nil || o.Route.Method == http.MethodOptions || o.Route.Method == http.MethodHead {
		return
	}
	origin := anyOrigin
	if i := slices.IndexFunc(c.Origins, func(o string) bool { return o != "*" }); i >= 0 {
		origin = c.Origins[i]
	}
	allowed := with(base, func(p *Probe) {
		p.Method, p.Identity, p.BodyKind = http.MethodOptions, string(semantics.NoToken), NoBody
		p.Headers[headerOrigin], p.Headers[headerMethod] = origin, o.Route.Method
		if len(c.Headers) > 0 {
			p.Headers[headerHeaders] = c.Headers[0]
		}
	})
	g.add(o, allowed, "preflight:allowed", nil)
	g.add(o, with(allowed, func(p *Probe) { p.Headers[headerOrigin] = unlistedOrigin }), "preflight:origin", nil)
	g.add(o, with(allowed, func(p *Probe) { p.Headers[headerHeaders] = unlistedHeader }), "preflight:header", nil)
	if i := slices.IndexFunc(methodProbes, func(m string) bool { return !slices.Contains(c.Methods, m) && !slices.Contains(safelisted, m) }); i >= 0 {
		g.add(o, with(allowed, func(p *Probe) { p.Headers[headerMethod] = methodProbes[i] }), "preflight:method", nil)
	}
}

// preflight is the reference decision of a preflight, and whether one was
// made. Where a route on the path answers for the requested method, as the
// gateway does, the route that method selects decides; otherwise a route
// the preflight's own OPTIONS selects decides if it has browser access.
// Any other preflight is an ordinary request.
func preflight(routes []semantics.Route, r Request) (Class, *semantics.Route, bool) {
	requested := slices.ContainsFunc(routes, func(route semantics.Route) bool {
		return route.CORS != nil && route.CORS.Requested && route.Path.Matches(r.Path)
	})
	selecting := r
	if requested {
		selecting.Method = r.Header.Get(headerMethod)
	}
	route, _ := choose(routes, selecting)
	switch {
	case requested && (route == nil || route.CORS == nil):
		return PreflightRefused, route, true
	case route == nil || route.CORS == nil || requested != route.CORS.Requested:
		return "", nil, false
	case requested && !route.Admits(r.Client):
		return Authz, route, true
	case route.CORS.Allows(r.Header.Get(headerOrigin), r.Header.Get(headerMethod), requestedHeaders(r.Header)):
		return PreflightAllowed, route, true
	}
	return PreflightRefused, route, true
}

// browserAllows is the browser's check of a preflight's answer (Fetch
// standard): the origin is allowed, the method is safelisted or allowed,
// and every requested header is allowed.
func browserAllows(p Probe, answer http.Header) bool {
	request := p.Request(0)
	origin := answer.Get("Access-Control-Allow-Origin")
	if origin != "*" && origin != request.Header.Get(headerOrigin) || origin == "" {
		return false
	}
	methods, headers := members(answer.Get("Access-Control-Allow-Methods")), members(answer.Get("Access-Control-Allow-Headers"))
	method := request.Header.Get(headerMethod)
	if !slices.Contains(safelisted, method) && !slices.Contains(methods, method) && !slices.Contains(methods, "*") {
		return false
	}
	for _, h := range requestedHeaders(request.Header) {
		if !slices.Contains(headers, "*") && !slices.ContainsFunc(headers, func(a string) bool { return strings.EqualFold(a, h) }) {
			return false
		}
	}
	return true
}

func requestedHeaders(header http.Header) []string { return members(header.Get(headerHeaders)) }

// members splits a comma-separated header value into its trimmed members.
func members(value string) []string {
	var out []string
	for _, member := range strings.Split(value, ",") {
		if member = strings.TrimSpace(member); member != "" {
			out = append(out, member)
		}
	}
	return out
}

// browserAccess reads the API's x-apiward-cors, as the gateway answers it.
func browserAccess(document map[string]any) *semantics.CORS {
	value, isObject := document[policy.CORSExtension].(map[string]any)
	if !isObject {
		return nil
	}
	return &semantics.CORS{Origins: texts(value["origins"]), Methods: texts(value["methods"]), Headers: texts(value["headers"]), Requested: true}
}
