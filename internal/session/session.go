// The session table, its entries and the random tokens behind them.

package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// NewToken returns 32 random bytes in URL-safe base64.
// tokenBytes of crypto/rand output (256 bits): enough that a token cannot
// be guessed. tokenLength is the length of every token NewToken returns.
const tokenBytes = 32

var tokenLength = base64.RawURLEncoding.EncodedLen(tokenBytes)

func NewToken() string {
	token := make([]byte, tokenBytes)
	rand.Read(token)
	return base64.RawURLEncoding.EncodeToString(token)
}

// Hash returns the hex SHA-256 of a token, the only form that is stored.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Session bounds. Gateways cap session lifetime and, per account, the
// sessions held at once; a global count alone lets one administrator lock
// every other out. Max is a safety bound on memory far above any team's
// administrators times DefaultPerAdmin.
const (
	DefaultPerAdmin = 8
	MaxPerAdmin     = 64
	Max             = 1024
)

// ErrFull is returned by Create when Max sessions are live.
var ErrFull = errors.New("session limit reached")

// Session is one authenticated administrator session. The server keeps only
// the SHA-256 of the session token; the token itself exists only in the
// administrator's cookie.
type Session struct {
	Admin      string
	Credential int64 // administrator credential version at login
	CSRF       string
	Reference  string        // non-secret identifier recorded in audit events
	Expires    time.Time     // absolute end of the session
	done       chan struct{} // closes when revoked or swept; long-lived readers stop too
}

// entry is a live session and its last use, in Unix nanoseconds: lookups
// record use under the read lock.
type entry struct {
	session  Session
	lastSeen atomic.Int64
}

// key is the SHA-256 of a session token, the table's index.
type key [sha256.Size]byte

// Table holds the live administrator sessions in memory. A restart ends
// every session; nothing about them is ever written to the database.
type Table struct {
	mu       sync.RWMutex
	byHash   map[key]*entry
	idle     time.Duration
	lifetime time.Duration
	perAdmin int
}

// New returns an empty table whose sessions end after idle without use or
// lifetime after sign-in; one administrator holds at most perAdmin of them.
func New(idle, lifetime time.Duration, perAdmin int) *Table {
	return &Table{byHash: map[key]*entry{}, idle: idle, lifetime: lifetime, perAdmin: perAdmin}
}

// Create starts a session and returns its token. Ended sessions are swept
// first. When admin already holds perAdmin sessions, the oldest of them
// ends; if Max sessions are still live, no session is created.
func (s *Table) Create(admin string, credential int64, now time.Time) (string, Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	held, oldest := 0, (*entry)(nil)
	var oldestHash key
	for hash, existing := range s.byHash {
		if existing.session.Admin != admin {
			continue
		}
		held++
		if oldest == nil || existing.session.Expires.Before(oldest.session.Expires) {
			oldest, oldestHash = existing, hash
		}
	}
	// Checked before the oldest session ends, so a refused sign-in signs
	// nobody out.
	full := len(s.byHash) >= Max
	if held >= s.perAdmin {
		full = len(s.byHash)-1 >= Max
	}
	if full {
		return "", Session{}, ErrFull
	}
	if held >= s.perAdmin {
		s.end(oldestHash)
	}
	token := NewToken()
	created := &entry{session: Session{
		Admin:      admin,
		Credential: credential,
		CSRF:       NewToken(),
		Reference:  Hash(token)[:16],
		Expires:    now.Add(s.lifetime),
		done:       make(chan struct{}),
	}}
	created.lastSeen.Store(now.UnixNano())
	s.byHash[sha256.Sum256([]byte(token))] = created
	return token, created.session, nil
}

func (s *Table) alive(e *entry, now time.Time) bool {
	return now.Before(e.session.Expires) && now.Before(time.Unix(0, e.lastSeen.Load()).Add(s.idle))
}

// Lookup returns the session for a token and records the activity. An unknown
// token is never adopted; an expired one is removed.
func (s *Table) Lookup(token string, now time.Time) (Session, string) {
	// A token of another length was never issued: it is not hashed.
	if len(token) != tokenLength {
		return Session{}, "no_session"
	}
	hash := key(sha256.Sum256([]byte(token)))
	s.mu.RLock()
	found := s.byHash[hash]
	live := found != nil && s.alive(found, now)
	if live {
		found.lastSeen.Store(now.UnixNano())
	}
	s.mu.RUnlock()
	switch {
	case found == nil:
		return Session{}, "no_session"
	case !live:
		s.mu.Lock()
		// Ended only if still the same entry and still not alive.
		if s.byHash[hash] == found && !s.alive(found, now) {
			s.end(hash)
		}
		s.mu.Unlock()
		return Session{}, "expired"
	}
	return found.session, ""
}

func (s *Table) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.end(sha256.Sum256([]byte(token)))
}

// end is called with s.mu held. Removing the entry makes closure one-shot.
func (s *Table) end(hash key) {
	if found := s.byHash[hash]; found != nil {
		close(found.session.done)
		delete(s.byHash, hash)
	}
}

func (s *Table) Active(token string, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	found := s.byHash[sha256.Sum256([]byte(token))]
	return found != nil && s.alive(found, now)
}

// RevokeAdmin ends every session of one administrator, as a credential change
// requires.
func (s *Table) RevokeAdmin(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, existing := range s.byHash {
		if existing.session.Admin == name {
			s.end(hash)
		}
	}
}

// Count returns the number of live sessions at now, ending those that are
// not, so each is closed for its readers.
func (s *Table) Count(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	return len(s.byHash)
}

// sweep ends every session that is no longer alive at now; s.mu is held.
// Sign-in and the limits report sweep, and every lookup ends its own ended
// session, so no background sweep is needed: the table never holds more
// than Max entries.
func (s *Table) sweep(now time.Time) {
	for hash, existing := range s.byHash {
		if !s.alive(existing, now) {
			s.end(hash)
		}
	}
}

// Closed returns a channel that closes when the session is revoked or swept.
func (s Session) Closed() <-chan struct{} { return s.done }
