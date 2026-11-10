// TLS session resumption to https upstreams: one session cache per loaded
// TLS profile, so a reloaded profile starts with none, and every session
// dropped after the configured lifetime, whatever the upstream's ticket
// allows.

package forward

import (
	"crypto/tls"
	"sync"
	"time"
)

// maxSessions bounds one profile's cache: one session per server name and
// address the profile's endpoints use.
const maxSessions = 64

// sessionCache is a tls.ClientSessionCache whose entries expire.
type sessionCache struct {
	lifetime time.Duration
	mu       sync.Mutex
	entries  map[string]session
}

type session struct {
	state *tls.ClientSessionState
	added time.Time
}

func newSessionCache(lifetime time.Duration) *sessionCache {
	return &sessionCache{lifetime: lifetime, entries: map[string]session{}}
}

// Get returns the session for key unless it has outlived the lifetime.
func (c *sessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Since(s.added) >= c.lifetime {
		delete(c.entries, key)
		return nil, false
	}
	return s.state, true
}

// Put stores state for key; a nil state removes the entry. A full cache
// first drops its oldest entry.
func (c *sessionCache) Put(key string, state *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if state == nil {
		delete(c.entries, key)
		return
	}
	if _, ok := c.entries[key]; !ok && len(c.entries) >= maxSessions {
		c.dropOldest()
	}
	c.entries[key] = session{state: state, added: time.Now()}
}

func (c *sessionCache) dropOldest() {
	var oldest string
	var at time.Time
	for key, s := range c.entries {
		if oldest == "" || s.added.Before(at) {
			oldest, at = key, s.added
		}
	}
	delete(c.entries, oldest)
}
