// The upstream connection pool: idle keep-alive connections per endpoint,
// each carrying one request at a time, lent to requests (exchange.go) and
// taken back, retired on a network reload and closed at shutdown.

package forward

import (
	"net/http"
	"sync"
	"sync/atomic"
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
	settings PoolSettings
	// connected marks a request's binding as holding a connection.
	connected func(*binding)
	// dials and reuses count the connections made and taken from the pool.
	dials, reuses atomic.Int64
	transport     *http.Transport // keep-alive; used only by NewClientConn
	network       func() *Network
	// mu is one lock for the whole pool: each hold is a few map operations,
	// so per-endpoint locks would add state without measurable gain.
	mu   sync.Mutex
	idle map[poolKey][]*pooledConn
	// current is the network of the newest request; idle connections made
	// under another are closed, so a reload never doubles the idle limit.
	current *Network
	closed  bool
}

func newConnPool(settings PoolSettings, base *http.Transport, network func() *Network, connected func(*binding)) *connPool {
	transport := base.Clone()
	transport.DisableKeepAlives = false
	return &connPool{settings: settings, transport: transport, network: network, connected: connected, idle: map[poolKey][]*pooledConn{}}
}

// take returns an idle connection to key, reserved for one request, or nil.
// Reserve runs outside the lock: on a connection the upstream has just
// closed, it calls the state hook synchronously, and the hook takes the lock.
func (p *connPool) take(key poolKey) *pooledConn {
	for {
		c := p.pop(key)
		if c == nil {
			return nil
		}
		if c.conn.Reserve() == nil {
			return c
		}
		c.conn.Close()
	}
}

// pop removes the newest idle connection to key from the pool, or returns nil.
func (p *connPool) pop(key poolKey) *pooledConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.idle[key]
	if len(list) == 0 {
		delete(p.idle, key)
		return nil
	}
	c := list[len(list)-1]
	p.idle[key] = list[:len(list)-1]
	c.idle = false
	c.timer.Stop()
	return c
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
	if p.closed || c.key.network != p.current || len(p.idle[c.key]) >= p.settings.MaxIdle {
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

// retire makes n the current network. Idle connections made under another
// network whose profile n holds unchanged (the same CA pin and client
// certificate, or no profile) move to n, so a reload that changes no TLS
// material causes no redial burst; the others, which no request can reuse,
// are closed.
func (p *connPool) retire(n *Network) {
	p.mu.Lock()
	if p.current == n {
		p.mu.Unlock()
		return
	}
	p.current = n
	var old []*pooledConn
	for key, list := range p.idle {
		if key.network == n {
			continue
		}
		delete(p.idle, key)
		if key.network.sameProfile(n, key.profile) {
			moved := key
			moved.network = n
			for _, c := range list {
				c.key = moved
			}
			p.idle[moved] = append(p.idle[moved], list...)
			continue
		}
		for _, c := range list {
			c.idle = false
			c.timer.Stop()
		}
		old = append(old, list...)
	}
	p.mu.Unlock()
	closeAll(old)
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

// Stats are the pool's figures for the metrics: connections idle now, and
// connections dialled and reused since the start.
type Stats struct{ Idle, Dials, Reuses int64 }

// Stats reads the pool's figures; the idle count takes the pool's lock.
func (p *connPool) stats() Stats {
	p.mu.Lock()
	idle := 0
	for _, list := range p.idle {
		idle += len(list)
	}
	p.mu.Unlock()
	return Stats{Idle: int64(idle), Dials: p.dials.Load(), Reuses: p.reuses.Load()}
}
