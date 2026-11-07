// The probe generator: per operation the forwarded request and the near misses around each control.

package probe

import (
	"slices"
	"strings"
	"unicode"

	"github.com/Alex-Zechariah-02/apiward/internal/exchange"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/semantics"
)

// methodProbes are the methods sent to a path that does not define them.
var methodProbes = []string{"GET", "PUT", "POST", "DELETE", "PATCH"}

// badTokens are the tokens that must not sign a caller in.
var badTokens = []semantics.Token{semantics.NoToken, semantics.Malformed, semantics.Expired, semantics.WrongIssuer, semantics.WrongAudience}

// unmatchedHost is a host no condition names (RFC 2606).
const unmatchedHost = "unmatched.invalid"

type generator struct {
	ops     []Operation
	routes  []semantics.Route
	ledger  *exchange.Ledger
	probed  map[string]bool // paths whose methods were probed
	probes  []Probe
	failure error
}

// Generate returns the probes of an exchange file for the operations
// migrate policy imports (see Operations). Every expectation comes from
// the reference evaluator over the gateway's own primitives; IDs are
// <operationId>:<kind>[:<variant>], in path and method order.
func Generate(document map[string]any, ledger *exchange.Ledger, opts Options) (*File, error) {
	ops, err := Operations(document, ledger, opts)
	if err != nil {
		return nil, err
	}
	g := &generator{ops: ops, routes: Routes(ops), ledger: ledger, probed: map[string]bool{}, probes: []Probe{}}
	written := slices.Clone(ops)
	slices.SortStableFunc(written, func(a, b Operation) int { return strings.Compare(a.Pointer, b.Pointer) })
	for _, o := range written {
		g.operation(o)
	}
	if g.failure != nil {
		return nil, g.failure
	}
	return &File{Version: Version, Probes: g.probes}, nil
}

// Routes returns the operations' routes, in their order.
func Routes(ops []Operation) []semantics.Route {
	routes := make([]semantics.Route, 0, len(ops))
	for _, o := range ops {
		routes = append(routes, o.Route)
	}
	return routes
}

func (g *generator) operation(o Operation) {
	base := Probe{Operation: o.ID, Method: o.Route.Method, Path: sample(o.Route.Path), Headers: chosenHeaders(o.Route),
		BodyKind: NoBody, Identity: string(semantics.NoToken)}
	if o.Schema != nil {
		base.BodyKind = Valid
	}
	var decisive []string // the controls a source most often decides differently
	if o.Route.Deny {
		decisive = []string{"access"}
	}
	if o.Route.Identity != nil {
		base.Identity, decisive = NoRole, append(decisive, "roles", "access")
		if len(o.Roles) > 0 {
			base.Identity = rolePrefix + o.Roles[0]
		}
	}
	forwarded := g.add(o, base, "forwarded", nil, decisive...)
	for _, miss := range nearMisses(o.Route.Path) {
		g.add(o, with(base, func(p *Probe) { p.Path = miss[1] }), "path:"+miss[0], nil)
	}
	g.methods(o, base)
	if o.Route.Identity != nil {
		for _, token := range badTokens {
			g.add(o, with(base, func(p *Probe) { p.Identity = string(token) }), "authn:"+string(token), nil, "auth")
		}
		for _, role := range o.Roles {
			g.add(o, with(base, func(p *Probe) { p.Identity = rolePrefix + role }), "role:"+role, nil, "roles", "access")
		}
		g.add(o, with(base, func(p *Probe) { p.Identity = NoRole }), "authz:no_role", nil, "roles", "access")
	}
	if o.Schema != nil {
		g.add(o, with(base, func(p *Probe) { p.BodyKind = Invalid }), "body:invalid", nil, "validation")
		g.add(o, with(base, func(p *Probe) { p.BodyKind = Oversized }), "body:oversize", nil, "size", "validation")
	}
	g.conditions(o, base)
	g.preflights(o, base)
	if forwarded {
		if o.Route.Rate != nil {
			g.add(o, base, "rate", fixed(Rate), "rate")
		}
		g.add(o, base, "error", fixed(Error), decisive...)
	}
}

// methods probes, once per path, each method the path does not define.
func (g *generator) methods(o Operation, base Probe) {
	if g.probed[o.Path] {
		return
	}
	g.probed[o.Path] = true
	for _, method := range methodProbes {
		defined := slices.ContainsFunc(g.ops, func(other Operation) bool { return other.Path == o.Path && other.Route.Method == method })
		if !defined {
			g.add(o, with(base, func(p *Probe) { p.Method, p.BodyKind = method, NoBody }), "method:"+method, nil)
		}
	}
}

// conditions probes an unmet host, a deeper wildcard host, and each
// header left out or sent in another case.
func (g *generator) conditions(o Operation, base Probe) {
	if len(o.Route.Hosts) > 0 {
		g.add(o, with(base, func(p *Probe) { p.Headers["Host"] = unmatchedHost }), "when:host", nil, "route")
		if domain, wildcard := strings.CutPrefix(o.Route.Hosts[0], "*"); wildcard {
			g.add(o, with(base, func(p *Probe) { p.Headers["Host"] = "a.b" + domain }), "when:depth", nil, "route")
		}
	}
	for _, h := range o.Route.Headers {
		g.add(o, with(base, func(p *Probe) { delete(p.Headers, h.Name) }), "when:without:"+h.Name, nil, "route")
		if swapped := swapCase(h.Value); swapped != h.Value {
			g.add(o, with(base, func(p *Probe) { p.Headers[h.Name] = swapped }), "when:case:"+h.Name, nil, "route")
		}
	}
}

// add writes a probe; its class is fixed or decided by the reference
// evaluator. It returns whether the probe is forwarded.
func (g *generator) add(o Operation, p Probe, kind string, class *Class, facets ...string) bool {
	body, err := Body(o, p.BodyKind)
	if err != nil {
		g.failure = err
		return false
	}
	p.ID = o.ID + ":" + kind
	if class == nil {
		decided, _ := Decide(g.routes, p.Request(int64(len(body))))
		class = &decided
	}
	member := ""
	switch {
	case strings.HasPrefix(kind, "when:"):
		member = policy.WhenExtension
	case strings.HasPrefix(kind, "preflight:"):
		member = "#/" + policy.CORSExtension
	}
	if !o.Route.Admits(Client) {
		facets, member = []string{"access"}, "#/"+policy.AddressesExtension
	}
	p.Expect = Expect{Class: *class, LedgerItem: g.item(o.Pointer, member, facets)}
	g.probes = append(g.probes, p)
	return *class == Forwarded
}

// item names the ledger item that predicts a difference on a probe: the
// one at member (inside the operation, or a root pointer #/...), else the
// first of the facets inside the operation, else the operation's route item.
func (g *generator) item(pointer, member string, facets []string) string {
	at := pointer + "/" + member
	if strings.HasPrefix(member, "#/") {
		at = member
	}
	find := func(match func(exchange.Item) bool) string {
		if i := slices.IndexFunc(g.ledger.Items, match); i >= 0 {
			return g.ledger.Items[i].ID
		}
		return ""
	}
	if id := find(func(i exchange.Item) bool { return member != "" && i.Target == at }); id != "" {
		return id
	}
	for _, facet := range facets {
		if id := find(func(i exchange.Item) bool {
			return i.Facet == facet && (i.Target == pointer || strings.HasPrefix(i.Target, pointer+"/"))
		}); id != "" {
			return id
		}
	}
	return find(func(i exchange.Item) bool { return i.Facet == "route" && i.Target == pointer })
}

func fixed(class Class) *Class { return &class }

// with returns a copy of the probe, headers included, changed by edit.
func with(p Probe, edit func(*Probe)) Probe {
	headers := map[string]string{}
	for name, value := range p.Headers {
		headers[name] = value
	}
	p.Headers = headers
	edit(&p)
	return p
}

// sample is a path the target takes: the target itself, or one segment under a deeper target.
func sample(rule semantics.PathRule) string {
	if rule.Match == semantics.DeeperOnly {
		return strings.TrimSuffix(rule.Value, "*") + "x"
	}
	return rule.Value
}

// nearMisses are the paths next to a target, as variant name and path.
func nearMisses(rule semantics.PathRule) [][2]string {
	base := strings.TrimSuffix(strings.TrimSuffix(rule.Value, "*"), "/")
	var misses [][2]string
	if rule.Match == semantics.DeeperOnly {
		misses = append(misses, [2]string{"slash", base + "/"}, [2]string{"deeper", base + "/x/y"})
		if base != "" {
			misses = append(misses, [2]string{"parent", base})
		}
	} else {
		misses = append(misses, [2]string{"deeper", base + "/x"})
		if base != "" {
			misses = append(misses, [2]string{"slash", base + "/"}, [2]string{"suffix", base + "x"})
		}
	}
	if upper := upperFirst(sample(rule)); upper != sample(rule) {
		misses = append(misses, [2]string{"upper", upper})
	}
	return misses
}

// upperFirst upper-cases the first letter of the path.
func upperFirst(path string) string {
	i := strings.IndexFunc(path, unicode.IsLower)
	if i < 0 {
		return path
	}
	return path[:i] + strings.ToUpper(path[i:i+1]) + path[i+1:]
}

func swapCase(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsUpper(r) {
			return unicode.ToLower(r)
		}
		return unicode.ToUpper(r)
	}, value)
}

// chosenHeaders are the host and headers that meet the route's conditions.
func chosenHeaders(route semantics.Route) map[string]string {
	headers := map[string]string{}
	if len(route.Hosts) > 0 {
		host := route.Hosts[0]
		if domain, wildcard := strings.CutPrefix(host, "*"); wildcard {
			host = "a" + domain
		}
		headers["Host"] = host
	}
	for _, h := range route.Headers {
		headers[h.Name] = h.Value
	}
	return headers
}
