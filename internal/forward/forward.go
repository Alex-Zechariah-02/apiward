// The upstream proxy: it sends each admitted request once, on an idle pooled
// connection or a new one, to the upstream bound to it, copies the response
// back through pooled buffers, and classifies an exchange that fails before
// any response.

package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"sync"
	"time"
)

// UpstreamTimeouts bounds the phases of one exchange with an upstream.
type UpstreamTimeouts struct {
	// Dial bounds establishing the connection.
	Dial time.Duration
	// ResponseHeader bounds the wait for the response header once the
	// request has been written, and each wait for the upstream to take more
	// of the request while it is written.
	ResponseHeader time.Duration
	// ReadIdle bounds each wait for more of the response body: a body that
	// sends nothing for this long ends the exchange.
	ReadIdle time.Duration
}

// Delivery of a request whose exchange failed before any response, recorded
// as the reason of its outcome. Only a request that never had a connection is
// known not to have reached the upstream; once it had one, the upstream may
// have acted on it, whatever the gateway answers.
var (
	errNotSent    = errors.New("the request was not sent")
	errMaybeSent  = errors.New("the request may have reached the upstream")
	errClientGone = errors.New("the client cancelled the request")
)

var (
	ErrResponseStalled  = errors.New("upstream response stalled")
	errProtocolSwitched = errors.New("upstream switched protocols")
)

// upstreamProxy forwards admitted requests to the upstream bound to them,
// using the standard library's reverse proxy over the connection pool, or
// over a transport that closes every connection when pooling is off.
type upstreamProxy struct {
	transport *http.Transport
	pool      *connPool // nil: every request on a new connection
	dialer    *net.Dialer
	network   func() *Network
	readIdle  time.Duration
	writeIdle time.Duration
	errorLog  *log.Logger
	buffers   copyBuffers
	ejector   *ejector
	proxy     *httputil.ReverseProxy // shared by every exchange
}

// copySize is the buffer the reverse proxy copies a response body through:
// the size it allocates for every response when it has no pool.
const copySize = 32 << 10

// copyBuffers lends the reverse proxy its copy buffers, so a response no
// longer allocates and clears 32 KiB. The proxy writes only the bytes each
// read returned, so nothing of an earlier response is ever sent; idle
// buffers are released by the garbage collector.
type copyBuffers struct{ pool sync.Pool }

func (c *copyBuffers) Get() []byte {
	if buffer, ok := c.pool.Get().(*[]byte); ok {
		return *buffer
	}
	return make([]byte, copySize)
}

func (c *copyBuffers) Put(buffer []byte) {
	c.pool.Put(&buffer)
}

// NewUpstreamProxy returns the proxy whose exchanges are bounded by timeouts.
// Every timeout must be positive: a zero would leave its phase unbounded.
// pool bounds the idle connections kept. network returns the current
// upstream network settings at each connection. The reverse proxy's own
// warnings, such as a failed response body read, go to logger.
func NewUpstreamProxy(timeouts UpstreamTimeouts, pool PoolSettings, network func() *Network, logger *slog.Logger) (*upstreamProxy, error) {
	if timeouts.Dial <= 0 || timeouts.ResponseHeader <= 0 || timeouts.ReadIdle <= 0 {
		return nil, errors.New("every upstream timeout must be positive")
	}
	if pool.MaxIdle < 0 || pool.MaxIdle > 0 && pool.IdleTimeout <= 0 {
		return nil, errors.New("a pool needs a positive idle timeout")
	}
	if logger == nil || network == nil {
		return nil, errors.New("a logger and the network settings are required")
	}
	protocols := new(http.Protocols)
	// HTTP/1.1 only: the pool reuses a connection for one request at a time.
	protocols.SetHTTP1(true)
	p := &upstreamProxy{
		network:   network,
		readIdle:  timeouts.ReadIdle,
		writeIdle: timeouts.ResponseHeader,
		errorLog:  slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		ejector:   newEjector(pool.EjectAfter),
	}
	// Every connection, whatever the policy or DNS said, is checked on the
	// address it is about to connect to.
	p.dialer = &net.Dialer{Timeout: timeouts.Dial, Control: p.checkAddress}
	p.transport = &http.Transport{
		// No Proxy function: the bound address is dialled directly, never
		// through a proxy named by the environment.
		DialContext:           p.dial,
		DialTLSContext:        p.dialTLS,
		ResponseHeaderTimeout: timeouts.ResponseHeader,
		// This transport sends a request on a new connection only. A
		// transport that keeps idle connections resends a request it deems
		// replayable (GET, HEAD, OPTIONS, or any request with an
		// Idempotency-Key and no body) when a reused connection fails,
		// though the upstream may already have acted on it; the pool reuses
		// connections with a narrower resend (exchange.go) that never repeats
		// a request with a body or one that may change data.
		DisableKeepAlives: true,
		// The upstream receives the client's Accept-Encoding, not one the
		// transport adds, and the client receives the upstream's bytes.
		DisableCompression: true,
		// Without a bound the transport reads up to 10 MiB of response
		// header per exchange from an upstream.
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
		Protocols:              protocols,
	}
	if pool.MaxIdle > 0 {
		p.pool = newConnPool(pool, p.transport, network, p.connected)
	}
	p.proxy = p.newReverseProxy()
	return p, nil
}

// MaxResponseHeaderBytes bounds the response header an upstream may send;
// a longer one fails the exchange. Envoy's default for HTTP/1 response
// headers is 80 KiB, NGINX's proxy_buffer_size 4 or 8 KiB.
const MaxResponseHeaderBytes = 64 << 10

// Stats returns the connection pool's figures; zero without a pool.
func (p *upstreamProxy) Stats() Stats {
	if p.pool == nil {
		return Stats{}
	}
	return p.pool.stats()
}

// Close closes the idle pooled connections; a request still in progress
// keeps its connection until it ends.
func (p *upstreamProxy) Close() {
	if p.pool != nil {
		p.pool.close()
	}
}

// roundTripper is what the reverse proxy sends through.
func (p *upstreamProxy) roundTripper() http.RoundTripper {
	if p.pool != nil {
		return p.pool
	}
	return p.transport
}

// Forward sends an admitted request to the upstream bound to it and copies
// the response to w; it is the enforcement handler's forwarder. The
// destination is the binding alone, and a request without a usable binding
// is sent nowhere. A failure before any response is returned for the handler
// to answer; a response that fails after it started is aborted by the
// reverse proxy with http.ErrAbortHandler, which it panics with only under a
// net/http server, so the handler must be served by one.
func (p *upstreamProxy) Forward(w http.ResponseWriter, r *http.Request) error {
	b := bindingOf(r.Context())
	if b == nil || b.destination.Endpoint() == nil {
		return fmt.Errorf("%w: %w", ErrNoUpstream, errNotSent)
	}
	address := b.destination.Endpoint().Address()
	if !p.ejector.admit(address, time.Now()) {
		return fmt.Errorf("%w: %w", errEjected, errNotSent)
	}
	// The exchange ends when the client goes away, through its request's
	// context, or when the response body stalls.
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	b.cancel = cancel
	if p.pool == nil {
		// Only the pool reports its connection itself.
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { p.connected(b) }})
	}
	defer func() { // a request that never connected, however it ends
		if !b.connected.Load() {
			p.ejector.settle(address, r.Context().Err() != nil)
		}
	}()
	p.proxy.ServeHTTP(w, r.WithContext(ctx))
	if b.failure == nil {
		return nil
	}
	delivery := DeliveryNone
	if b.connected.Load() {
		if r.Context().Err() != nil {
			delivery = DeliveryCancelled
		} else {
			delivery = DeliveryUnknown
		}
	}
	return ExchangeFailure(b.failure, delivery)
}

// connected records that b's exchange holds a connection: a probe of an
// ejected endpoint settles at once, not when its exchange ends.
func (p *upstreamProxy) connected(b *binding) {
	if b.connected.CompareAndSwap(false, true) {
		p.ejector.result(b.destination.Endpoint().Address(), true, time.Now())
	}
}

// RoundTrip sends the outbound request through the pool or the transport and
// notes how long the upstream took to answer with its headers.
func (p *upstreamProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	b := bindingOf(req.Context())
	start := time.Now()
	res, err := p.roundTripper().RoundTrip(req)
	if err == nil && b != nil {
		b.upstream = time.Since(start)
	}
	return res, err
}

// idleBody is an upstream response body each of whose reads may wait at most
// idle for data. A read that waits longer calls stall, which ends the
// exchange: the transport closes the connection and the blocked read fails.
// One timer serves every read; it runs only while a read is waiting.
type idleBody struct {
	io.ReadCloser
	idle  time.Duration
	timer *time.Timer
}

func newIdleBody(body io.ReadCloser, idle time.Duration, stall func()) *idleBody {
	timer := time.AfterFunc(idle, stall)
	timer.Stop()
	return &idleBody{ReadCloser: body, idle: idle, timer: timer}
}

func (b *idleBody) Read(p []byte) (int, error) {
	b.timer.Reset(b.idle)
	n, err := b.ReadCloser.Read(p)
	b.timer.Stop()
	return n, err
}
