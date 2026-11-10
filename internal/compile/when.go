// Host and header conditions: their compiler checks, how a request is
// matched against them, and the rules that keep conditioned operations on
// one target and method unambiguous and never weaker than the unconditioned
// operation they sit beside.

package compile

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

const (
	maxHostLength  = 253
	maxLabelLength = 63
	maxHeaderValue = 256
)

// condition is a compiled When: lower-case host patterns and header
// conditions with canonical names.
type condition struct {
	hosts   []string
	headers []policy.HeaderCondition
}

// Inbound is what a request offers to conditions: its Host value as received
// (any case, any port) and its header fields.
type Inbound struct {
	Host   string
	Header http.Header
}

// compileWhen checks an operation's conditions: at least one, 1-16 lower-case
// DNS host patterns, 1-8 header conditions on distinct names a header schema
// could declare (checkHeaderSchema's rule), each with a visible value.
func compileWhen(w *policy.When, i int) (*condition, error) {
	if len(w.Hosts) == 0 && len(w.Headers) == 0 {
		return nil, policy.Invalid("INVALID_VALUE", "operations[%d].when", i)
	}
	if len(w.Hosts) > policy.MaxWhenHosts || len(w.Headers) > policy.MaxWhenHeaders {
		return nil, policy.Invalid("LIMIT_EXCEEDED", "operations[%d].when", i)
	}
	c := &condition{}
	for j, host := range w.Hosts {
		if !hostPattern(host) || slices.Contains(c.hosts, host) {
			return nil, policy.Invalid("INVALID_VALUE", "operations[%d].when.hosts[%d]", i, j)
		}
		c.hosts = append(c.hosts, host)
	}
	for j, h := range w.Headers {
		name := http.CanonicalHeaderKey(h.Name)
		if !isHeaderName(name) || IsGatewayHeader(name) || unforwardedHeaders[name] || slices.ContainsFunc(c.headers, func(o policy.HeaderCondition) bool { return o.Name == name }) {
			return nil, policy.Invalid("INVALID_VALUE", "operations[%d].when.headers[%d].name", i, j)
		}
		if !headerValue(h.Value) {
			return nil, policy.Invalid("INVALID_VALUE", "operations[%d].when.headers[%d].value", i, j)
		}
		c.headers = append(c.headers, policy.HeaderCondition{Name: name, Value: h.Value})
	}
	return c, nil
}

// hostPattern accepts a lower-case DNS name, optionally after "*.".
func hostPattern(host string) bool {
	name := strings.TrimPrefix(host, "*.")
	if name == "" || len(name) > maxHostLength {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > maxLabelLength || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// headerValue accepts visible ASCII with inner spaces: a received value has
// its surrounding spaces removed, so such a value could never match.
func headerValue(value string) bool {
	if value == "" || len(value) > maxHeaderValue || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for _, c := range []byte(value) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// count ranks conditions: the host list counts once, each header once.
func (c *condition) count() int {
	n := len(c.headers)
	if len(c.hosts) > 0 {
		n++
	}
	return n
}

// holds reports whether a request meets every condition. host is already
// lower-case without a port. A header sent more than once never holds, so
// the gateway and an upstream cannot read different values.
func (c *condition) holds(host string, header http.Header) bool {
	if len(c.hosts) > 0 && !slices.ContainsFunc(c.hosts, func(p string) bool { return hostMatches(p, host) }) {
		return false
	}
	for _, h := range c.headers {
		values := header.Values(h.Name)
		if len(values) != 1 || values[0] != h.Value {
			return false
		}
	}
	return true
}

// hostMatches compares a pattern with a host name; "*.d" matches any name
// ending in ".d" (one label or more), never d itself.
func hostMatches(pattern, host string) bool {
	domain, wildcard := strings.CutPrefix(pattern, "*.")
	if !wildcard {
		return pattern == host
	}
	return len(host) > len(domain)+1 && strings.HasSuffix(host, "."+domain)
}

// requestHost lower-cases the Host value and removes its port.
func requestHost(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return strings.ToLower(host)
}

// overlaps reports whether one request could meet both conditions.
func (c *condition) overlaps(o *condition) bool {
	if len(c.hosts) > 0 && len(o.hosts) > 0 && !slices.ContainsFunc(c.hosts, func(a string) bool {
		return slices.ContainsFunc(o.hosts, func(b string) bool { return hostMatches(a, b) || hostMatches(b, a) || a == b })
	}) {
		return false
	}
	for _, h := range c.headers {
		for _, g := range o.headers {
			if h.Name == g.Name && h.Value != g.Value {
				return false
			}
		}
	}
	return true
}

// checkVariants refuses, per target and method, two conditioned operations
// of equal rank that one request could meet (TARGET_COLLISION), and a
// conditioned operation weaker than the unconditioned one (CONDITION_WEAKER).
// It sorts each variant list most conditions first and points each variant
// with an unconditioned sibling at that sibling's rate counter.
func checkVariants(targets map[string]*target, ops []policy.Operation) error {
	for _, t := range targets {
		for method, variants := range t.variants {
			slices.SortStableFunc(variants, func(a, b *Rule) int { return b.when.count() - a.when.count() })
			if err := checkCollisions(variants); err != nil {
				return err
			}
			for _, v := range variants {
				base := t.methods[method]
				if base == nil {
					continue
				}
				if weaker(v, base, ops[v.index], ops[base.index]) {
					return policy.Invalid("CONDITION_WEAKER", "operations[%d].when", v.index)
				}
				// Alternating conditions must not multiply the plain
				// operation's quota: the variant counts on its counter.
				v.counter = base.operation
			}
		}
	}
	return nil
}

// checkCollisions refuses the first variant, in the given order, that one
// request could select together with an earlier variant of equal rank. Two
// conditions on the same header names overlap only when every value is equal,
// so variants are grouped by their names and values: within one name set only
// equal values are compared, which keeps the common case (one header, many
// values) linear; variants with other name sets are compared pairwise.
func checkCollisions(variants []*Rule) error {
	var byValues, byNames map[string][]*Rule
	rank := -1
	for _, v := range variants {
		if v.when.count() != rank {
			rank, byValues, byNames = v.when.count(), map[string][]*Rule{}, map[string][]*Rule{}
		}
		names, values := v.when.keys()
		collides := slices.ContainsFunc(byValues[values], func(o *Rule) bool { return o.when.overlaps(v.when) })
		for other, group := range byNames {
			if other != names && slices.ContainsFunc(group, func(o *Rule) bool { return o.when.overlaps(v.when) }) {
				collides = true
			}
		}
		if collides {
			return policy.Invalid("TARGET_COLLISION", "operations[%d].when", v.index)
		}
		byValues[values] = append(byValues[values], v)
		byNames[names] = append(byNames[names], v)
	}
	return nil
}

// keys returns the condition's header names, and its names with their values,
// each sorted by name in one string. Names are header tokens and values
// visible ASCII, so the separators cannot occur in either.
func (c *condition) keys() (names, values string) {
	headers := slices.SortedFunc(slices.Values(c.headers), func(a, b policy.HeaderCondition) int { return strings.Compare(a.Name, b.Name) })
	var n, v strings.Builder
	for _, h := range headers {
		n.WriteString(h.Name + "\x00")
		v.WriteString(h.Name + "\x00" + h.Value + "\x01")
	}
	return n.String(), v.String()
}

// weaker reports whether a conditioned rule admits a request its
// unconditioned sibling would refuse: allowed where the sibling is denied,
// public where it is protected, a role the sibling does not permit, a rate
// rule missing, keyed differently or looser, a body the sibling refuses or
// a different or larger one, or a header schema the sibling has but it lacks.
func weaker(v, base *Rule, op, baseOp policy.Operation) bool {
	if !v.permitted {
		return false
	}
	if !base.permitted || v.public && !base.public {
		return true
	}
	for role := range v.roles {
		if !base.roles[role] {
			return true
		}
	}
	if base.rate != nil && (v.rate == nil || v.rateKey != base.rateKey || v.rate.count > base.rate.count || v.rate.window < base.rate.window) {
		return true
	}
	if v.body != nil && (base.body == nil || v.body.maxBytes > base.body.maxBytes || !sameJSON(op.Body.Schema, baseOp.Body.Schema)) {
		return true
	}
	return base.headers != nil && !sameJSON(op.Headers, baseOp.Headers)
}

// sameJSON compares two schemas after removing insignificant space; a
// different member order counts as different, which can only refuse.
func sameJSON(a, b json.RawMessage) bool {
	var x, y bytes.Buffer
	return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && bytes.Equal(x.Bytes(), y.Bytes())
}
