// Exchange operations the gateway will enforce, each reduced to the gateway's own primitives.

package probe

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/exchange"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/semantics"
)

// Operation members of the exchange file (README "Exchange file").
const (
	memberTarget   = "x-apiward-target"
	memberAccess   = "x-apiward-access"
	memberRoles    = "x-apiward-roles"
	memberRate     = "x-apiward-rate"
	memberMaxBytes = "x-apiward-max-bytes"
)

// methods an operation may have, in the order probes are written.
var methods = []string{"get", "put", "post", "delete", "patch", "options", "head", "trace"}

// Options are the policy path's defaults the exchange file leaves out.
type Options struct {
	MaxBodyBytes int64 // body limit of an operation without x-apiward-max-bytes
}

// Operation is one exchange operation the gateway will enforce.
type Operation struct {
	ID, Pointer string
	Path        string // the OpenAPI path
	Schema      any    // the JSON body schema, nil when the operation takes no body
	Roles       []string
	Route       semantics.Route // the gateway's decision primitives
}

// Operations returns the operations migrate policy imports: those a route
// item of the ledger points at, without a looser item that is not
// accepted. Their routes are in the gateway's precedence order: exact
// targets, then deeper targets, longest first. Roles are those of
// x-apiward-roles, as imported with --with-permits.
func Operations(document map[string]any, ledger *exchange.Ledger, opts Options) ([]Operation, error) {
	paths, _ := document["paths"].(map[string]any)
	var out []Operation
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		item, _ := paths[path].(map[string]any)
		for _, method := range methods {
			op, isObject := item[method].(map[string]any)
			pointer := "#/paths/" + escape(path) + "/" + method
			if !isObject || !imported(ledger, pointer) {
				continue
			}
			o, err := Describe(document, op, path, strings.ToUpper(method), opts)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", strings.ToUpper(method), policy.Clip(path), err)
			}
			o.Pointer = pointer
			if !settled(ledger, "#/"+policy.CORSExtension) {
				o.Route.CORS = nil // migrate policy leaves the API's browser access out
			}
			out = append(out, o)
		}
	}
	slices.SortStableFunc(out, func(a, b Operation) int { return precedence(a.Route.Path, b.Route.Path) })
	return out, nil
}

// settled reports whether migrate policy keeps the API setting at pointer:
// no looser item that is not accepted points to it.
func settled(ledger *exchange.Ledger, pointer string) bool {
	return !slices.ContainsFunc(ledger.Items, func(item exchange.Item) bool {
		return item.Target == pointer && item.Class == exchange.Approximated && item.Direction == exchange.Looser && !item.Accepted
	})
}

// imported reports whether migrate policy imports the operation at pointer.
func imported(ledger *exchange.Ledger, pointer string) bool {
	routed := false
	for _, item := range ledger.Items {
		inside := item.Target == pointer || strings.HasPrefix(item.Target, pointer+"/")
		if inside && item.Class == exchange.Approximated && item.Direction == exchange.Looser && !item.Accepted {
			return false
		}
		routed = routed || item.Facet == "route" && item.Target == pointer
	}
	return routed
}

// Describe reads one operation of the document as the gateway enforces
// it: its target, access, sign-in, roles, rate, body, conditions and the
// API's allow list.
func Describe(document, op map[string]any, path, method string, opts Options) (Operation, error) {
	allow, err := addresses(document[policy.AddressesExtension])
	if err != nil {
		return Operation{}, err
	}
	id, _ := op["operationId"].(string)
	target := cmp.Or(text(op[memberTarget]), importTarget(path))
	route := semantics.Route{Operation: id, Method: method, Path: semantics.PathRule{Match: semantics.Exact, Value: target},
		Deny: text(op[memberAccess]) == "deny", Allow: allow, CORS: browserAccess(document)}
	if strings.HasSuffix(target, "*") {
		route.Path.Match = semantics.DeeperOnly
	}
	o := Operation{ID: id, Path: path}
	if signedIn(document, op) {
		route.Identity = &semantics.Identity{Scheme: semantics.IssuerKey, ChecksAudience: true, ChecksExpiry: true}
		o.Roles = texts(op[memberRoles])
		route.Roles = &semantics.Roles{Source: semantics.TokenClaim, Claim: "roles", Rule: semantics.AllowList, Values: o.Roles}
	}
	if rate, isObject := op[memberRate].(map[string]any); isObject {
		route.Rate = &semantics.Rate{Algorithm: semantics.WeightedSliding, Count: number(rate["count"]), Window: number(rate["window_seconds"])}
	}
	if body, _ := op["requestBody"].(map[string]any); body != nil {
		content, _ := body["content"].(map[string]any)
		media, _ := content["application/json"].(map[string]any)
		o.Schema = media["schema"]
		route.Schema = o.Schema != nil
		route.MaxBytes = cmp.Or(number(op[memberMaxBytes]), opts.MaxBodyBytes)
	}
	if err := conditions(&route, op[policy.WhenExtension]); err != nil {
		return Operation{}, err
	}
	o.Route = route
	return o, nil
}

// signedIn is the import's rule: sign-in unless the operation's security,
// or the root's when it states none, is an empty list.
func signedIn(document, op map[string]any) bool {
	security, stated := op["security"]
	if !stated {
		security, stated = document["security"]
	}
	list, isList := security.([]any)
	return !stated || !isList || len(list) > 0
}

// conditions reads x-apiward-when, as the policy states it.
func conditions(route *semantics.Route, value any) error {
	if value == nil {
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var when policy.When
	if err := policy.DecodeStrict(data, &when); err != nil {
		return fmt.Errorf("%s: %w", policy.WhenExtension, err)
	}
	route.Hosts = when.Hosts
	for _, h := range when.Headers {
		route.Headers = append(route.Headers, semantics.Header{Name: h.Name, Value: h.Value})
	}
	return nil
}

// addresses reads the API's allow list; nil when there is none.
func addresses(value any) ([]netip.Prefix, error) {
	if value == nil {
		return nil, nil
	}
	ranges := texts(value)
	allow := make([]netip.Prefix, 0, len(ranges))
	for _, r := range ranges {
		prefix, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", policy.AddressesExtension, err)
		}
		allow = append(allow, prefix)
	}
	return allow, nil
}

// importTarget is the import's target for a path: a last-segment template
// becomes the deeper target of its parent.
func importTarget(path string) string {
	cut := strings.LastIndex(path, "/") + 1
	if strings.HasPrefix(path[cut:], "{") {
		return path[:cut] + "*"
	}
	return path
}

// precedence orders exact targets first, then deeper ones, longest first.
func precedence(a, b semantics.PathRule) int {
	deeper := func(r semantics.PathRule) int {
		if r.Match == semantics.Exact {
			return 0
		}
		return 1
	}
	return cmp.Or(cmp.Compare(deeper(a), deeper(b)), cmp.Compare(len(b.Value), len(a.Value)))
}
