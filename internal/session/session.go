// The session table, its entries and the random tokens behind them.

package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// NewToken returns 32 random bytes in URL-safe base64.
func NewToken() string {
	token := make([]byte, 32)
	rand.Read(token)
	return base64.RawURLEncoding.EncodeToString(token)
}

// Hash returns the hex SHA-256 of a token, the only form that is stored.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Max is the most sessions held at once.
const Max = 64

// ErrFull is returned by Create when Max sessions are live.
var ErrFull = errors.New("session limit reached")

// Session is one authenticated administrator session. The server keeps only
// the SHA-256 of the session token; the token itself exists only in the
// administrator's cookie.
type Session struct {
	Admin      string
	Credential int64 // administrator credential version at login
	CSRF       string
	Reference  string // non-secret identifier recorded in audit events
	lastSeen   time.Time
	Expires    time.Time     // absolute end of the session
	done       chan struct{} // closes when revoked or swept; long-lived readers stop too
}

// Table holds the live administrator sessions in memory. A restart ends
// every session; nothing about them is ever written to the database.
type Table struct {
	mu       sync.Mutex
	byHash   map[string]*Session
	idle     time.Duration
	lifetime time.Duration
}

func New(idle, lifetime time.Duration) *Table {
	return &Table{byHash: map[string]*Session{}, idle: idle, lifetime: lifetime}
}

// Create starts a session and returns its token. Expired sessions are swept
// first; if the limit is still reached, no session is created.
func (s *Table) Create(admin string, credential int64, now time.Time) (string, Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, existing := range s.byHash {
		if !s.alive(existing, now) {
			s.end(hash)
		}
	}
	if len(s.byHash) >= Max {
		return "", Session{}, ErrFull
	}
	token := NewToken()
	hash := Hash(token)
	created := &Session{
		Admin:      admin,
		Credential: credential,
		CSRF:       NewToken(),
		Reference:  hash[:16],
		lastSeen:   now,
		Expires:    now.Add(s.lifetime),
		done:       make(chan struct{}),
	}
	s.byHash[hash] = created
	return token, *created, nil
}

func (s *Table) alive(entry *Session, now time.Time) bool {
	return now.Before(entry.Expires) && now.Before(entry.lastSeen.Add(s.idle))
}

// Lookup returns the session for a token and records the activity. An unknown
// token is never adopted; an expired one is removed.
func (s *Table) Lookup(token string, now time.Time) (Session, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := Hash(token)
	entry := s.byHash[hash]
	if entry == nil {
		return Session{}, "no_session"
	}
	if !s.alive(entry, now) {
		s.end(hash)
		return Session{}, "expired"
	}
	entry.lastSeen = now
	return *entry, ""
}

func (s *Table) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.end(Hash(token))
}

// end is called with s.mu held. Removing the entry makes closure one-shot.
func (s *Table) end(hash string) {
	if entry := s.byHash[hash]; entry != nil {
		close(entry.done)
		delete(s.byHash, hash)
	}
}

func (s *Table) Active(token string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.byHash[Hash(token)]
	return entry != nil && s.alive(entry, now)
}

// RevokeAdmin ends every session of one administrator, as a credential change
// requires.
func (s *Table) RevokeAdmin(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, entry := range s.byHash {
		if entry.Admin == name {
			s.end(hash)
		}
	}
}

// Count returns the number of sessions held, live or not yet swept.
func (s *Table) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byHash)
}

// Closed returns a channel that closes when the session is revoked or swept.
func (s Session) Closed() <-chan struct{} { return s.done }
