// Package connections caps a listener's open connections: past the cap, a new
// connection is accepted and closed at once, before any byte is read, so an
// overload of connections cannot exhaust memory or descriptors. The data,
// redirect, metrics and Admin API listeners each have their own cap.
package connections

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Auxiliary caps the metrics and Admin API listeners: they serve a few
// scrapers, health probes and Dashboard tabs, and 64 leaves room for each
// while bounding the descriptors they can take from the data listener.
const Auxiliary = 64

// listener accepts at most max open connections, and with perAddress set
// at most that many from one client address; refused is called once per
// connection closed at a cap.
type listener struct {
	net.Listener
	max     int64
	open    atomic.Int64
	refused func()
	// perAddress is 0 (no per-address bound) or each address's share;
	// byAddress counts the open connections of each address, under mu.
	perAddress int
	mu         sync.Mutex
	byAddress  map[netip.Addr]int
}

// Cap returns l limited to max open connections; refused counts each
// connection closed at the cap.
func Cap(l net.Listener, max int, refused func()) net.Listener {
	return &listener{Listener: l, max: int64(max), refused: refused}
}

// CapPerAddress is Cap with each client address also limited to perAddress
// open connections (nginx limit_conn, HAProxy's per-source stick tables), so
// one client cannot hold every place; 0 sets no per-address bound.
func CapPerAddress(l net.Listener, max, perAddress int, refused func()) net.Listener {
	return &listener{Listener: l, max: int64(max), refused: refused, perAddress: perAddress, byAddress: map[netip.Addr]int{}}
}

// takeAddress counts a connection from addr in, or reports that addr holds
// its share. Addresses the listener cannot read are not bounded.
func (l *listener) takeAddress(addr netip.Addr) bool {
	if l.perAddress == 0 || !addr.IsValid() {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byAddress[addr] >= l.perAddress {
		return false
	}
	l.byAddress[addr]++
	return true
}

// giveAddress counts a connection from addr out.
func (l *listener) giveAddress(addr netip.Addr) {
	if l.perAddress == 0 || !addr.IsValid() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byAddress[addr] <= 1 {
		delete(l.byAddress, addr)
		return
	}
	l.byAddress[addr]--
}

// peer is the client address of conn, or the zero address.
func peer(conn net.Conn) netip.Addr {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// Accept returns the next connection under the cap. A connection over it is
// closed and never returned: no request exists, so none is recorded.
func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		addr := peer(conn)
		if l.open.Add(1) <= l.max {
			if l.takeAddress(addr) {
				return &capped{Conn: conn, listener: l, addr: addr}, nil
			}
		}
		l.open.Add(-1)
		conn.Close()
		l.refused()
	}
}

// capped gives its place back the first time it is closed.
type capped struct {
	net.Conn
	listener *listener
	addr     netip.Addr
	once     sync.Once
}

func (c *capped) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.listener.open.Add(-1)
		c.listener.giveAddress(c.addr)
	})
	return err
}
