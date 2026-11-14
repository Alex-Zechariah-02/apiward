// Package connections caps a listener's open connections: past the cap, a new
// connection is accepted and closed at once, before any byte is read, so an
// overload of connections cannot exhaust memory or descriptors. The data,
// redirect, metrics and Admin API listeners each have their own cap.
package connections

import (
	"net"
	"sync"
	"sync/atomic"
)

// Auxiliary caps the metrics and Admin API listeners: they serve a few
// scrapers, health probes and Dashboard tabs, and 64 leaves room for each
// while bounding the descriptors they can take from the data listener.
const Auxiliary = 64

// listener accepts at most max open connections; refused is called once per
// connection closed at the cap.
type listener struct {
	net.Listener
	max     int64
	open    atomic.Int64
	refused func()
}

// Cap returns l limited to max open connections; refused counts each
// connection closed at the cap.
func Cap(l net.Listener, max int, refused func()) net.Listener {
	return &listener{Listener: l, max: int64(max), refused: refused}
}

// Accept returns the next connection under the cap. A connection over it is
// closed and never returned: no request exists, so none is recorded.
func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.open.Add(1) <= l.max {
			return &capped{Conn: conn, listener: l}, nil
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
	once     sync.Once
}

func (c *capped) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.listener.open.Add(-1) })
	return err
}
