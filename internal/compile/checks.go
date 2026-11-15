// Policy count, permit, deny-all and upstream address checks, and the
// warnings a generation is published with.

package compile

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// checkCounts refuses a policy with more upstreams, APIs, operations, roles
// or permits than limits allow, and limits out of range.
func checkCounts(p policy.Policy, limits policy.Limits) error {
	limits, err := limits.Resolve()
	if err != nil {
		return policy.Invalid("LIMIT_EXCEEDED", "")
	}
	counts := []struct {
		field string
		count int
		limit int
	}{
		{"upstreams", len(p.Upstreams), limits.APIs},
		{"apis", len(p.APIs), limits.APIs},
		{"operations", len(p.Operations), limits.Operations},
		{"roles", len(p.Roles), limits.Roles},
		{"permits", len(p.Permits), limits.Permits},
	}
	for _, l := range counts {
		if l.count > l.limit {
			return policy.Invalid("LIMIT_EXCEEDED", "%s", l.field)
		}
	}
	return nil
}

// checkPermits validates the role declarations and the permits that refer to
// them, and records each permit on its operation's rule. Unknown roles and
// operations are rejected, so a reference can never grant anything by
// accident. It returns the declared roles.
func checkPermits(p policy.Policy, rules map[string]*Rule) (map[string]bool, error) {
	roles := map[string]bool{}
	for i, r := range p.Roles {
		if err := policy.CheckID(r.ID, "roles[%d].id", i); err != nil {
			return nil, err
		}
		if roles[r.ID] {
			return nil, policy.Invalid("DUPLICATE_ID", "roles[%d].id", i)
		}
		roles[r.ID] = true
	}

	for i, permit := range p.Permits {
		if !roles[permit.Role] {
			return nil, policy.Invalid("UNKNOWN_REFERENCE", "permits[%d].role", i)
		}
		r, ok := rules[permit.Operation]
		if !ok {
			return nil, policy.Invalid("UNKNOWN_REFERENCE", "permits[%d].operation", i)
		}
		// A permit on an operation that needs no authentication could never
		// apply, so the two declarations contradict each other.
		if r.public {
			return nil, policy.Invalid("INVALID_VALUE", "permits[%d].operation", i)
		}
		if r.roles[permit.Role] {
			return nil, policy.Invalid("DUPLICATE_ID", "permits[%d]", i)
		}
		r.roles[permit.Role] = true
	}
	return roles, nil
}

// isLoopbackDial accepts only literal loopback addresses, so a destination can
// neither be resolved through DNS nor expanded from request placeholders.
func isLoopbackDial(dial string) bool {
	addr, err := netip.ParseAddrPort(dial)
	return err == nil && addr.Port() != 0 && addr.Addr().IsLoopback()
}

// DenyAll reports whether the policy can admit no request at all: no
// operation is both allowed and public, and no permit names an allowed
// operation, so no authenticated request can pass RBAC either; a permit on
// an operation whose access is deny admits nothing. Only such a policy may
// become the first base of an installation or the base that ends a recovery.
func DenyAll(p policy.Policy) bool {
	allowed := map[string]bool{}
	for _, op := range p.Operations {
		if op.Access != "allow" {
			continue
		}
		if op.Auth == "none" {
			return false
		}
		allowed[op.ID] = true
	}
	return !slices.ContainsFunc(p.Permits, func(permit policy.Permit) bool { return allowed[permit.Operation] })
}

// Warnings names what in the generation is valid but likely unintended, for
// the log line of each publication: a prefix target "/x/*" without the exact
// target "/x", which it does not match, and an upstream reached over plain
// http at an address other than loopback, where requests, identity
// assertions and bodies cross the network unencrypted.
func (g *Generation) Warnings() []string {
	items := []string{}
	for _, t := range g.prefixes {
		base := strings.TrimSuffix(t.prefix, "/")
		if base != "" && g.exact[base] == nil {
			items = append(items, fmt.Sprintf("target %s does not match %s or %s/; declare %s as well if it should be served", t.pattern, base, base, base))
		}
	}
	for _, e := range g.endpoints {
		if e.scheme == "http" && !e.ip.IsLoopback() {
			items = append(items, fmt.Sprintf("%s (%s) is plain http to a non-loopback address: requests, identity assertions and bodies cross the network unencrypted; use https with a client certificate", e.field, e.address))
		}
	}
	slices.Sort(items)
	return items
}
