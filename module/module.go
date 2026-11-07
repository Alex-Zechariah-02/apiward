// Package module is the contract for controls compiled into the gateway
// binary. A module registers itself from init with Register, takes its
// settings from one member of a policy operation, compiles them once per
// published policy and then checks requests at one fixed phase of the
// request pipeline.
//
// The order of phases is fixed in the gateway, never configured: a module
// cannot run before the checks its phase follows, cannot skip a later stage
// and never forwards anything. A refusal or failure ends the request. The
// gateway's five built-in controls (jwt, rbac, rate, body, validation) are
// registered under their own IDs in every build, which reserves those IDs.
//
// A Check sees only a copy of the request's method, path, client address,
// headers and verified identity: no body, no token and no connection. It must
// not perform network or file I/O and must not keep mutable package-level
// state; per-key state belongs in a Table.
package module

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sync"
)

// Phase is the point of the request pipeline at which a module runs.
type Phase int

const (
	Ingress   Phase = iota + 1 // after the ingress checks, before a policy is captured; sees no policy settings
	Identity                   // after routing and access, following token verification
	Authorise                  // following roles and blocked accounts
	Traffic                    // following the rate limit
	Validate                   // following body and header validation
)

// String names the phase as status reports and records do.
func (p Phase) String() string {
	switch p {
	case Ingress:
		return "ingress"
	case Identity:
		return "identity"
	case Authorise:
		return "authorise"
	case Traffic:
		return "traffic"
	case Validate:
		return "validate"
	}
	return fmt.Sprintf("Phase(%d)", int(p))
}

// Info identifies a module.
type Info struct {
	ID      string // 1-32 of a-z, 0-9, '_'; unique; also the policy member name
	Phase   Phase
	Version string // the module's own version
}

// Operation is the policy operation a module's settings belong to.
type Operation struct {
	ID, API, Method, Target string
}

// Control is a module.
type Control interface {
	Info() Info
	// Compile runs inside the gateway's policy compiler, once per published
	// policy and operation, never per request. raw is this module's member of
	// the operation, nil when absent. A nil Check means the module is not
	// configured for the operation. An error or a panic refuses the policy.
	Compile(op Operation, raw json.RawMessage) (Check, error)
}

// Check decides one request using only r and the data compiled into it.
type Check interface {
	Check(ctx context.Context, r *Request) Result
}

// Request is the read-only view of a request a Check receives.
type Request struct {
	Method, Path, ClientAddress string
	Header                      http.Header // a copy: changing it changes nothing
	Subject                     string      // empty before or without a verified token
	Roles                       []string
	Operation, API              string // empty in the Ingress phase
}

type outcome int

const (
	invalid outcome = iota // the zero Result, never built by Pass, Refuse or Fail
	pass
	refuse
	fail
)

// Result is a Check's decision. Only Pass, Refuse and Fail build one; the
// zero Result is treated as a failure.
type Result struct {
	outcome outcome
	status  int
	code    string
}

var codeFormat = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Pass lets the request continue.
func Pass() Result { return Result{outcome: pass} }

// Refuse ends the request with status (400-499) and the error code code. A
// status outside that range or a malformed code becomes a failure.
func Refuse(status int, code string) Result {
	if status < 400 || status > 499 || !codeFormat.MatchString(code) {
		return Fail("invalid refusal")
	}
	return Result{outcome: refuse, status: status, code: code}
}

// Fail ends the request with 503 gateway_unavailable; reason is recorded
// with the module's ID and must not contain request data.
func Fail(reason string) Result { return Result{outcome: fail, code: reason} }

// Passed, Refused and Failed report the decision; Status and Code are the
// refusal's answer, and Reason a failure's reason.
func (r Result) Passed() bool  { return r.outcome == pass }
func (r Result) Refused() bool { return r.outcome == refuse }
func (r Result) Failed() bool  { return r.outcome == fail || r.outcome == invalid }
func (r Result) Status() int   { return r.status }
func (r Result) Code() string  { return r.code }

// Reason is a failure's reason; a zero Result reads "no result".
func (r Result) Reason() string {
	if r.outcome == invalid {
		return "no result"
	}
	return r.code
}

var idFormat = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// Builtins are the IDs of the gateway's own controls.
var builtins = []string{"jwt", "rbac", "rate", "body", "validation"}

// reserved are operation members that are not module settings.
var reserved = []string{"id", "api", "method", "target", "access", "auth", "headers", "when"}

var (
	mu       sync.RWMutex
	controls = map[string]Control{}
)

// Register adds a module. Call it from init. It panics on an invalid or
// duplicate ID, an unknown phase, or an ID that names another operation
// member, so a build with a conflicting module never starts.
func Register(c Control) {
	info := c.Info()
	switch {
	case !idFormat.MatchString(info.ID):
		panic(fmt.Sprintf("module: invalid ID %q", info.ID))
	case info.Phase < Ingress || info.Phase > Validate:
		panic(fmt.Sprintf("module %s: invalid phase %d", info.ID, info.Phase))
	case slices.Contains(reserved, info.ID):
		panic(fmt.Sprintf("module %s: the ID names an operation member", info.ID))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := controls[info.ID]; ok {
		panic(fmt.Sprintf("module %s: already registered", info.ID))
	}
	controls[info.ID] = c
}

// Registered lists every registered module, built-ins included, sorted by
// phase and then ID.
func Registered() []Info {
	var out []Info
	for _, c := range sorted(true) {
		out = append(out, c.Info())
	}
	return out
}

// Extensions returns the registered modules that are not built in, sorted
// by phase and then ID: the ones whose checks the pipeline runs and whose
// policy members the gateway reads.
func Extensions() []Control { return sorted(false) }

func sorted(withBuiltins bool) []Control {
	mu.RLock()
	defer mu.RUnlock()
	var out []Control
	for id, c := range controls {
		if withBuiltins || !slices.Contains(builtins, id) {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b Control) int {
		x, y := a.Info(), b.Info()
		return cmp.Or(cmp.Compare(x.Phase, y.Phase), cmp.Compare(x.ID, y.ID))
	})
	return out
}
