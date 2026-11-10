// What the enforcement handler depends on, and its construction.

package pipeline

import (
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/module"
)

// DefaultMaxBody is the global request body ceiling when none is set.
const DefaultMaxBody = 16 << 10

// DefaultMaxInFlight bounds the requests inside enforcement at once. On one
// vCPU, up to 500 requests in flight raised resident memory by about 70 MiB
// (about 140 KiB each), so the default bounds overload to about 35 MiB.
const DefaultMaxInFlight = 256

// DefaultIPv6RatePrefix is the prefix an IPv6 client's rate key is masked
// to: one /64 is what a single subscriber is usually given, so a client
// rotating addresses inside it shares one counter.
const DefaultIPv6RatePrefix = 64

// MinIPv6RatePrefix is the widest IPv6 rate key: a /48 is a whole site.
const MinIPv6RatePrefix = 48

// Limits bound the handler's work; a zero member selects its default.
type Limits struct {
	MaxBodyBytes   int64
	MaxInFlight    int64
	IPv6RatePrefix int
}

// Handler enforces the published policy on every request and, only when every
// stage passes, binds the permitted upstream and hands the request to its
// forwarder. Any other outcome is answered here and never forwarded. It is an
// http.Handler, so any net/http server can run it.
type Handler struct {
	authority    Authority
	audit        *audit.AuditLog
	observations *monitor.Observations
	limiter      *Limiter
	clock        Clock
	auditTimeout time.Duration
	// maxBodyBytes is the global request body ceiling. A larger declared
	// length is refused before any policy work, and the body read for an
	// operation is bounded by it as well as by the operation's own ceiling.
	maxBodyBytes int64
	// maxInFlight bounds the requests inside enforcement; inFlight counts
	// them.
	maxInFlight int64
	inFlight    atomic.Int64
	// ipv6Prefix masks an IPv6 client address for its rate key.
	ipv6Prefix int
	forward    Forward
	// held is set while an embedded gateway has not started its own
	// listeners; every request is then refused at capture, so nothing is
	// admitted before the Admin API and metrics can observe it.
	held atomic.Bool
	// extensions are the compiled-in modules other than the built-ins, and
	// ingress the checks of those that run in the Ingress phase.
	extensions []module.Info
	ingress    []compile.ModuleCheck
}

// Forward sends an admitted request to the upstream bound in its context
// and copies the response to w. It returns an error when the exchange failed;
// the handler then answers with the status forwardFailure gives it, unless a
// response was already started. A response it cannot complete after it
// started is aborted by panicking with http.ErrAbortHandler, as net/http's
// reverse proxy does.
type Forward func(w http.ResponseWriter, r *http.Request) error

// Authority is the published state the pipeline reads. It has no method that
// publishes policy, trust or containment: the pipeline can only ask that an
// expired generation be ended.
type Authority interface {
	// Current returns the one generation a request captures; nil serves nothing.
	Current() *compile.Generation
	// Expired asks the publisher to end what expired in g.
	Expired(g *compile.Generation)
	Verifier() *Verifier
	Blocked() *store.BlockedAccounts
	// Addresses returns the blocked address list; nil until it was read.
	Addresses() *store.BlockedAddresses
}

// Deps is everything the handler needs; New refuses a missing one.
type Deps struct {
	Authority    Authority
	Audit        *audit.AuditLog
	Observations *monitor.Observations
	Limiter      *Limiter
	Clock        Clock
	AuditTimeout time.Duration
	Limits       Limits
	// Forward is called only for admitted requests.
	Forward Forward
}

// New returns the enforcement handler for the policy d.Authority
// publishes.
func New(d Deps) (*Handler, error) {
	if d.Authority == nil || d.Audit == nil || d.Observations == nil || d.Limiter == nil || d.Forward == nil {
		return nil, errors.New("the enforcement handler needs a controller and a forwarder")
	}
	limits := d.Limits
	if limits.MaxBodyBytes <= 0 {
		limits.MaxBodyBytes = DefaultMaxBody
	}
	if limits.MaxInFlight <= 0 {
		limits.MaxInFlight = DefaultMaxInFlight
	}
	if limits.IPv6RatePrefix == 0 {
		limits.IPv6RatePrefix = DefaultIPv6RatePrefix
	}
	if limits.IPv6RatePrefix < MinIPv6RatePrefix || limits.IPv6RatePrefix > 128 {
		return nil, errors.New("the IPv6 rate prefix must be 48 to 128")
	}
	extensions := module.Extensions()
	ingress, err := compileIngress(extensions)
	if err != nil {
		return nil, err
	}
	h := &Handler{
		authority: d.Authority, audit: d.Audit, observations: d.Observations,
		limiter: d.Limiter, clock: d.Clock, auditTimeout: d.AuditTimeout,
		maxBodyBytes: limits.MaxBodyBytes, maxInFlight: limits.MaxInFlight, ipv6Prefix: limits.IPv6RatePrefix,
		forward: d.Forward, ingress: ingress,
	}
	for _, c := range extensions {
		h.extensions = append(h.extensions, c.Info())
	}
	return h, nil
}

// hold refuses every request at capture while on, so an embedded gateway
// admits nothing before its Admin API and metrics can observe it.
func (h *Handler) Hold(on bool) { h.held.Store(on) }
