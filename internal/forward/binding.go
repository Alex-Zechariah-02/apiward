// The upstream binding carried from enforcement to the proxy, and its errors.

package forward

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// Forwarding failures that decide the gateway's own answer; any other error
// means the upstream could not be reached or failed.
var (
	ErrNoUpstream      = errors.New("no upstream for the request")
	ErrUpstreamTimeout = errors.New("upstream timed out")
)

// binding is the trusted upstream decision carried in the request context:
// the compiled destination. Only this package can attach it; no header or
// placeholder can. It also holds the state of the one exchange made for it,
// which only the forwarder writes: one allocation per request instead of a
// proxy, its closures and a client trace.
type binding struct {
	destination  compile.Destination
	forwardedFor string        // validated X-Forwarded-For chain from a trusted proxy; empty for untrusted peers
	connected    atomic.Bool   // a connection to the upstream was held
	upstream     time.Duration // from sending the request to the response headers
	cancel       context.CancelCauseFunc
	failure      error // why the exchange failed before any response
}

type bindingKey struct{}

// Bind returns ctx carrying the destination the compiled rule chose: the one
// upstream the request may reach and the path it is forwarded with, plus the
// validated X-Forwarded-For chain when the peer is a trusted proxy (empty
// otherwise). It is the only way to attach a binding.
func Bind(ctx context.Context, d compile.Destination, forwardedFor string) context.Context {
	return context.WithValue(ctx, bindingKey{}, &binding{destination: d, forwardedFor: forwardedFor})
}

// Bound returns the destination ctx is bound to, if a binding is attached.
func Bound(ctx context.Context) (compile.Destination, bool) {
	b := bindingOf(ctx)
	if b == nil {
		return compile.Destination{}, false
	}
	return b.destination, true
}

// UpstreamTime is how long the upstream took to answer the request bound in
// ctx, from sending it to its response headers (monotonic clock); zero when
// no response arrived.
func UpstreamTime(ctx context.Context) time.Duration {
	if b := bindingOf(ctx); b != nil {
		return b.upstream
	}
	return 0
}

func bindingOf(ctx context.Context) *binding {
	b, _ := ctx.Value(bindingKey{}).(*binding)
	return b
}
