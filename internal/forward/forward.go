// The upstream proxy: it sends each admitted request, once and on a new
// connection, to the upstream bound to it, copies the response back, and
// classifies an exchange that fails before any response.

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
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// UpstreamTimeouts bounds the phases of one exchange with an upstream.
type UpstreamTimeouts struct {
	// Dial bounds establishing the connection.
	Dial time.Duration
	// ResponseHeader bounds the wait for the response header once the
	// request has been written.
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
// using the standard library's reverse proxy over one dedicated transport.
type upstreamProxy struct {
	transport *http.Transport
	dialer    *net.Dialer
	network   func() *Network
	readIdle  time.Duration
	errorLog  *log.Logger
}

// NewUpstreamProxy returns the proxy whose exchanges are bounded by timeouts.
// Every timeout must be positive: a zero would leave its phase unbounded.
// network returns the current upstream network settings at each connection.
// The reverse proxy's own warnings, such as a failed response body read, go to
// logger.
func NewUpstreamProxy(timeouts UpstreamTimeouts, network func() *Network, logger *slog.Logger) (*upstreamProxy, error) {
	if timeouts.Dial <= 0 || timeouts.ResponseHeader <= 0 || timeouts.ReadIdle <= 0 {
		return nil, errors.New("every upstream timeout must be positive")
	}
	if logger == nil || network == nil {
		return nil, errors.New("a logger and the network settings are required")
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	p := &upstreamProxy{
		network:  network,
		readIdle: timeouts.ReadIdle,
		errorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	// Every connection, whatever the policy or DNS said, is checked on the
	// address it is about to connect to.
	p.dialer = &net.Dialer{Timeout: timeouts.Dial, Control: p.checkAddress}
	p.transport = &http.Transport{
		// No Proxy function: the bound address is dialled directly, never
		// through a proxy named by the environment.
		DialContext:           p.dialer.DialContext,
		DialTLSContext:        p.dialTLS,
		ResponseHeaderTimeout: timeouts.ResponseHeader,
		// Every request is sent once, on a new connection. A transport that
		// keeps idle connections resends a request it deems replayable (GET,
		// HEAD, OPTIONS, or any request with an Idempotency-Key and no body)
		// when a reused connection fails, though the upstream may already
		// have acted on it.
		DisableKeepAlives: true,
		// The upstream receives the client's Accept-Encoding, not one the
		// transport adds, and the client receives the upstream's bytes.
		DisableCompression: true,
		Protocols:          protocols,
	}
	return p, nil
}

// forward sends an admitted request to the upstream bound to it and copies
// the response to w; it is the enforcement handler's forwarder. The
// destination is the binding alone, and a request without a usable binding is
// sent nowhere. A failure before any response is returned for the handler to
// answer; a response that fails after it started is aborted by the reverse
// proxy with http.ErrAbortHandler, which it panics with only under a net/http
// server, so the handler must be served by one.
func (p *upstreamProxy) Forward(w http.ResponseWriter, r *http.Request) error {
	d, bound := Bound(r.Context())
	if !bound || d.Endpoint() == nil || !compile.IsCanonical(d.Path()) {
		return fmt.Errorf("%w: %w", ErrNoUpstream, errNotSent)
	}

	// The exchange ends when the client goes away, through its request's
	// context, or when the response body stalls.
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	})

	var failure error
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(pr *httputil.ProxyRequest) { rewriteToUpstream(pr, d.Endpoint(), d.Path()) },
		Transport: p.transport,
		ErrorLog:  p.errorLog,
		ModifyResponse: func(res *http.Response) error {
			// Every protocol switch is refused at ingress, so an upstream that
			// switches anyway is not followed into a tunnel. The proxy closes
			// the response, and with it the connection.
			if res.StatusCode == http.StatusSwitchingProtocols {
				return errProtocolSwitched
			}
			// Only the gateway assigns the response's correlation reference.
			res.Header.Del("X-Request-Id")
			res.Header.Add("Via", via(res.ProtoMajor, res.ProtoMinor))
			res.Body = newIdleBody(res.Body, p.readIdle, func() { cancel(ErrResponseStalled) })
			return nil
		},
		// The enforcement handler answers the client; only the cause is kept.
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) { failure = err },
	}
	proxy.ServeHTTP(w, r.WithContext(ctx))
	if failure == nil {
		return nil
	}
	return ExchangeFailure(failure, connected.Load(), r.Context().Err() != nil)
}

// ExchangeFailure classifies an exchange that failed before any response by
// what is known about delivery and, for the gateway's answer, whether the
// upstream timed out.
func ExchangeFailure(err error, connected, clientGone bool) error {
	switch {
	case !connected:
		return fmt.Errorf("%w: %w", errNotSent, err)
	case clientGone:
		return fmt.Errorf("%w: %w", errClientGone, err)
	}
	// Once connected, only the response-header timeout ends the exchange
	// with a timeout error.
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return fmt.Errorf("%w: %w: %w", ErrUpstreamTimeout, errMaybeSent, err)
	}
	return fmt.Errorf("%w: %w", errMaybeSent, err)
}

// rewriteToUpstream addresses the outbound request to the endpoint with the
// bound path and sets the gateway's forwarding metadata. The reverse proxy calls it
// after removing the hop-by-hop fields, including every field the client
// named in Connection, and the client's Forwarded and X-Forwarded-* fields,
// so the client can neither remove nor supply anything set here.
func rewriteToUpstream(pr *httputil.ProxyRequest, e *compile.Endpoint, path string) {
	in := pr.In.URL
	// The client's target as admitted: the query unparsed, unparsable
	// parameters included, and the path in its received encoding unless the
	// API's forward rule rewrote it. The gateway does not interpret the
	// query, so it cannot read it differently from the upstream. The outbound
	// request keeps the inbound Host unless the upstream asks for its own;
	// either reaches the upstream but never chooses it.
	rawPath := in.RawPath
	if path != in.Path {
		rawPath = "" // the rewritten path is canonical, so its encoding is unambiguous
	}
	pr.Out.URL = &url.URL{
		Scheme:     e.Scheme(),
		Host:       e.Address(),
		Path:       path,
		RawPath:    rawPath,
		RawQuery:   in.RawQuery,
		ForceQuery: in.ForceQuery,
	}
	if e.Host() != "" {
		pr.Out.Host = e.Host()
	}
	// The direct peer's address, the inbound Host and the inbound protocol.
	pr.SetXForwarded()
	pr.Out.Header.Add("Via", via(pr.In.ProtoMajor, pr.In.ProtoMinor))
}

// via is the gateway's Via field value for a message received with the given
// HTTP version (RFC 9110, section 7.6.3).
func via(major, minor int) string {
	return strconv.Itoa(major) + "." + strconv.Itoa(minor) + " gateway"
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
