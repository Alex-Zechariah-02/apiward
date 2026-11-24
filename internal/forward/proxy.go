// The reverse proxy every exchange shares: it addresses the outbound
// request to the bound endpoint, sets the gateway's forwarding metadata and
// screens the response, reading each exchange's binding from its context.

package forward

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
)

// newReverseProxy is the one reverse proxy every exchange shares; each reads
// its binding from the request's context.
func (p *upstreamProxy) newReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			b := bindingOf(pr.In.Context())
			rewriteToUpstream(pr, b.destination.Endpoint(), b.destination.Path(), b.forwardedFor)
		},
		Transport:  p,
		ErrorLog:   p.errorLog,
		BufferPool: &p.buffers,
		// A response with a declared length is otherwise held in the server's
		// buffer, headers included, until it ends; flushing every 100 ms
		// (Traefik's default) passes a slow response on as it arrives. Event
		// streams and bodies without a length are flushed at once regardless.
		FlushInterval:  100 * time.Millisecond,
		ModifyResponse: p.modifyResponse,
		// The enforcement handler answers the client; only the cause is kept.
		ErrorHandler: func(_ http.ResponseWriter, r *http.Request, err error) { bindingOf(r.Context()).failure = err },
	}
}

// modifyResponse refuses a protocol switch, removes the upstream's
// correlation reference, adds Via and bounds each wait for the body.
func (p *upstreamProxy) modifyResponse(res *http.Response) error {
	// Every protocol switch is refused at ingress, so an upstream that
	// switches anyway is not followed into a tunnel. The proxy closes the
	// response, and with it the connection.
	if res.StatusCode == http.StatusSwitchingProtocols {
		return errProtocolSwitched
	}
	// Only the gateway assigns the response's correlation reference.
	res.Header.Del("X-Request-Id")
	res.Header.Add("Via", via(res.ProtoMajor, res.ProtoMinor))
	b := bindingOf(res.Request.Context())
	res.Body = newIdleBody(res.Body, p.readIdle, func() { b.cancel(ErrResponseStalled) })
	return nil
}

// rewriteToUpstream addresses the outbound request to the endpoint with the
// bound path and sets the gateway's forwarding metadata. The reverse proxy calls it
// after removing the hop-by-hop fields, including every field the client
// named in Connection, and the client's Forwarded and X-Forwarded-* fields,
// so the client can neither remove nor supply anything set here.
func rewriteToUpstream(pr *httputil.ProxyRequest, e *compile.Endpoint, path, forwardedFor string) {
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
	// When the peer is a trusted proxy, keep the validated chain with the peer
	// appended instead of discarding it.
	pr.SetXForwarded()
	if forwardedFor != "" {
		pr.Out.Header.Set("X-Forwarded-For", forwardedFor)
	}
	pr.Out.Header.Add("Via", via(pr.In.ProtoMajor, pr.In.ProtoMinor))
}

// via is the Via entry for a message of the given protocol version: HTTP/2
// and later have no minor version (RFC 9110 section 7.6.3). The common
// versions are constants, so no string is built per exchange.
func via(major, minor int) string {
	switch {
	case major == 1 && minor == 1:
		return "1.1 gateway"
	case major == 2:
		return "2 gateway"
	case major > 2:
		return strconv.Itoa(major) + " gateway"
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(minor) + " gateway"
}
