// The upstream connection pool: idle keep-alive connections per endpoint,
// each carrying one request at a time. A request is sent once: only
// ClientConn.RoundTrip sends, which has no retry, so the transport's resend
// of a replayable request on a failed reused connection never runs, and a
// request that fails on a reused connection fails like any exchange that had
// a connection.

package forward

import (
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

// PoolSettings bound the idle connections kept to upstreams.
type PoolSettings struct {
	// MaxIdle is the most idle connections kept per endpoint; 0 sends every
	// request on a new connection closed after its response.
	MaxIdle int
	// IdleTimeout closes a connection idle this long. It must stay below the
	// upstream server's own idle timeout, so the gateway, not the upstream,
	// ends an idle connection.
	IdleTimeout time.Duration
	// EjectAfter is how many consecutive connection failures eject an
	// endpoint, so requests to it fail at once for a while; 0 never ejects.
	EjectAfter int
}

// poolKey names the connections one request may reuse: the same endpoint
// under the same loaded network settings, so a reload never reuses a
// connection made with an earlier TLS profile.
type poolKey struct {
	network                  *Network
	scheme, address, profile string
}

// pooledConn is one keep-alive connection. idle and its place in the pool's
// list change only under the pool's lock; the timer runs only while idle.
type pooledConn struct {
	conn  *http.ClientConn
	key   poolKey
	timer *time.Timer
	idle  bool
}

// connPool lends idle connections to requests and takes them back when
// their exchange has ended. Connections are closed outside the lock, since
// closing one may call its state hook, which takes the lock.
type connPool struct {
	settings  PoolSettings
	transport *http.Transport // keep-alive; used only by NewClientConn
	network   func() *Network
	mu        sync.Mutex
	idle      map[poolKey][]*pooledConn
	closed    bool
}

func newConnPool(settings PoolSettings, base *http.Transport, network func() *Network) *connPool {
	transport := base.Clone()
	transport.DisableKeepAlives = false
	return &connPool{settings: settings, transport: transport, network: network, idle: map[poolKey][]*pooledConn{}}
}

// RoundTrip sends req once, on an idle connection to its bound endpoint or
// a new one. Forward has checked the binding. The request's GotConn trace
// hook is called once a connection is held, since ClientConn.RoundTrip does
// not call it: from then on a failure may have reached the upstream.
func (p *connPool) RoundTrip(req *http.Request) (*http.Response, error) {
	d, _ := Bound(req.Context())
	e := d.Endpoint()
	key := poolKey{network: p.network(), scheme: e.Scheme(), address: e.Address(), profile: e.Profile()}
	c := p.take(key)
	reused := c != nil
	if c == nil {
		conn, err := p.transport.NewClientConn(req.Context(), key.scheme, key.address)
		if err != nil {
			return nil, err
		}
		if err := conn.Reserve(); err != nil {
			conn.Close()
			return nil, err
		}
		c = &pooledConn{conn: conn, key: key}
		c.timer = time.AfterFunc(p.settings.IdleTimeout, func() {
			if p.unlist(c) {
				c.conn.Close()
			}
		})
		c.timer.Stop()
		// Called when the exchange ends (the connection is available again)
		// or the connection fails.
		conn.SetStateHook(func(*http.ClientConn) { p.changed(c) })
	}
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Reused: reused, WasIdle: reused})
	}
	return c.conn.RoundTrip(req)
}

// take returns an idle connection to key, reserved for one request, or nil.
func (p *connPool) take(key poolKey) *pooledConn {
	var stale []*pooledConn
	defer func() { closeAll(stale) }()
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.idle[key]
	for len(list) > 0 {
		c := list[len(list)-1]
		list = list[:len(list)-1]
		p.idle[key] = list
		c.idle = false
		c.timer.Stop()
		if c.conn.Reserve() == nil {
			return c
		}
		stale = append(stale, c)
	}
	delete(p.idle, key)
	return nil
}

// changed puts c back once its exchange has ended, or drops it when it can
// no longer be used or the pool is full or closed.
func (p *connPool) changed(c *pooledConn) {
	if c.conn.Err() != nil {
		p.unlist(c)
		c.conn.Close()
		return
	}
	if c.conn.Available() == 0 {
		return
	}
	p.mu.Lock()
	if c.idle {
		p.mu.Unlock()
		return
	}
	if p.closed || len(p.idle[c.key]) >= p.settings.MaxIdle {
		p.mu.Unlock()
		c.conn.Close()
		return
	}
	c.idle = true
	p.idle[c.key] = append(p.idle[c.key], c)
	c.timer.Reset(p.settings.IdleTimeout)
	p.mu.Unlock()
}

// unlist takes c out of the pool and reports whether it was idle there. A
// connection lent to a request is not idle, so an idle timer that fires as
// the connection is taken leaves it alone.
func (p *connPool) unlist(c *pooledConn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !c.idle {
		return false
	}
	c.idle = false
	c.timer.Stop()
	list := p.idle[c.key]
	for i, other := range list {
		if other == c {
			p.idle[c.key] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	return true
}

// close closes every idle connection and keeps no more; connections still
// carrying a request close when it ends.
func (p *connPool) close() {
	var all []*pooledConn
	p.mu.Lock()
	p.closed = true
	for key, list := range p.idle {
		for _, c := range list {
			c.idle = false
			c.timer.Stop()
		}
		all = append(all, list...)
		delete(p.idle, key)
	}
	p.mu.Unlock()
	closeAll(all)
}

func closeAll(conns []*pooledConn) {
	for _, c := range conns {
		c.conn.Close()
	}
}
