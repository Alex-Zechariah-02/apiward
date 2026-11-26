// Sending one request on a pooled upstream connection. Only
// ClientConn.RoundTrip sends, which has no retry of its own. A GET, HEAD or
// OPTIONS without a body that fails on a reused idle connection before any
// response byte (the upstream closed the kept connection) is sent once more
// on a new connection, as Go's transport and Caddy do; any other request is
// sent once, and one that fails on a reused connection fails like any
// exchange that had a connection.

package forward

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

// RoundTrip sends req on an idle connection to its bound endpoint or a new
// one, and resends it once on a new connection as the file header states.
// Forward has checked the binding. Once a connection is held the binding is
// marked connected: from then on a failure may have reached the upstream.
func (p *connPool) RoundTrip(req *http.Request) (*http.Response, error) {
	b := bindingOf(req.Context())
	e := b.destination.Endpoint()
	key := poolKey{network: p.network(), scheme: e.Scheme(), address: e.Address(), profile: e.Profile()}
	p.retire(key.network)
	c := p.take(key)
	reused := c != nil
	if reused {
		p.reuses.Add(1)
	} else {
		var err error
		if c, err = p.dial(req.Context(), key); err != nil {
			return nil, err
		}
	}
	p.connected(b)
	if !reused || !resendable(req) {
		return c.conn.RoundTrip(req)
	}
	var answered atomic.Bool
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { answered.Store(true) }}
	res, err := c.conn.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if err == nil || answered.Load() || req.Context().Err() != nil {
		return res, err
	}
	fresh, dialErr := p.dial(req.Context(), key)
	if dialErr != nil {
		return nil, err
	}
	return fresh.conn.RoundTrip(req)
}

// resendable reports a request that changes no data (RFC 9110 section 9.2.1)
// and carries no body, so sending it twice changes nothing upstream.
func resendable(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return req.Body == nil || req.Body == http.NoBody
	}
	return false
}

// dial makes a new connection to key, reserved for one request, whose state
// hook returns it to the pool when its exchange ends.
func (p *connPool) dial(ctx context.Context, key poolKey) (*pooledConn, error) {
	p.dials.Add(1)
	conn, err := p.transport.NewClientConn(ctx, key.scheme, key.address)
	if err != nil {
		return nil, err
	}
	if err := conn.Reserve(); err != nil {
		conn.Close()
		return nil, err
	}
	c := &pooledConn{conn: conn, key: key}
	c.timer = time.AfterFunc(p.settings.IdleTimeout, func() {
		if p.unlist(c) {
			c.conn.Close()
		}
	})
	c.timer.Stop()
	// Called when the exchange ends (the connection is available again)
	// or the connection fails.
	conn.SetStateHook(func(*http.ClientConn) { p.changed(c) })
	return c, nil
}
