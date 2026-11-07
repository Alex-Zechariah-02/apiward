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
)

const DefaultMaxBody = 16 << 10

// Handler enforces the published policy on every request and, only when every
// stage passes, binds the permitted upstream and hands the request to its
// forwarder. Any other outcome is answered here and never forwarded. It is an
// http.Handler, so any net/http server can run it.
type Handler struct {
	authority    Authority
	audit        *audit.AuditLog
	observations *monitor.Observations
	Limiter      *Limiter
	clock        Clock
	auditTimeout time.Duration
	// maxBodyBytes is the global request body ceiling. A larger declared
	// length is refused before any policy work, and the body read for an
	// operation is bounded by it as well as by the operation's own ceiling.
	maxBodyBytes int64
	forward      Forward
	// held is set while an embedded gateway has not started its own
	// listeners; every request is then refused at capture, so nothing is
	// admitted before the Admin API and metrics can observe it.
	held atomic.Bool
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
	// MaxBodyBytes of zero or less selects the default ceiling.
	MaxBodyBytes int64
	// Forward is called only for admitted requests.
	Forward Forward
}

// New returns the enforcement handler for the policy d.Authority
// publishes.
func New(d Deps) (*Handler, error) {
	if d.Authority == nil || d.Audit == nil || d.Observations == nil || d.Limiter == nil || d.Forward == nil {
		return nil, errors.New("the enforcement handler needs a controller and a forwarder")
	}
	maxBodyBytes := d.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBody
	}
	return &Handler{
		authority: d.Authority, audit: d.Audit, observations: d.Observations,
		Limiter: d.Limiter, clock: d.Clock, auditTimeout: d.AuditTimeout,
		maxBodyBytes: maxBodyBytes, forward: d.Forward,
	}, nil
}

// hold refuses every request at capture while on, so an embedded gateway
// admits nothing before its Admin API and metrics can observe it.
func (h *Handler) Hold(on bool) { h.held.Store(on) }
