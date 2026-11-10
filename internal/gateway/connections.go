// The data listener's connection cap: past the configured number of open
// connections, a new one is accepted and closed at once, before any byte is
// read, so an overload of connections cannot exhaust memory or descriptors.

package gateway

import (
	"net"
	"sync"
	"sync/atomic"
)

// cappedListener accepts at most max open connections; refused calls once
// per connection closed at the cap.
type cappedListener struct {
	net.Listener
	max     int64
	open    atomic.Int64
	refused func()
}

func capConnections(l net.Listener, max int, refused func()) *cappedListener {
	return &cappedListener{Listener: l, max: int64(max), refused: refused}
}

// Accept returns the next connection under the cap. A connection over it is
// closed and never returned: no request exists, so none is recorded.
func (l *cappedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.open.Add(1) <= l.max {
			return &cappedConn{Conn: conn, listener: l}, nil
		}
		l.open.Add(-1)
		conn.Close()
		l.refused()
	}
}

// cappedConn gives its place back the first time it is closed.
type cappedConn struct {
	net.Conn
	listener *cappedListener
	once     sync.Once
}

func (c *cappedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.listener.open.Add(-1) })
	return err
}
