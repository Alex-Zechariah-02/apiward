// Sign-in failure throttling: per administrator name and per client address.

package admin

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Failed-attempt limits for sign-ins, enrolments and password changes.
const (
	// A name is locked for lockoutPeriod after maxNameFailures failures within
	// failureWindow (OWASP Authentication Cheat Sheet: lock for a period, not
	// for good), so a guesser gets five tries per name every 15 minutes.
	maxNameFailures = 5
	lockoutPeriod   = 15 * time.Minute
	failureWindow   = 15 * time.Minute
	// maxSourceFailures stops one client address for lockoutPeriod after this
	// many failures in a window, whichever names it tried; it is ten names'
	// worth of tries, so one person mistyping never meets it.
	maxSourceFailures = 50
	// maxEntries bounds the counters held in memory (about 100 bytes each);
	// when it is reached and pruning frees none, every new attempt is refused.
	maxEntries = 10_000
	// maxHashing bounds concurrent argon2id hashing at 19 MiB each, so password
	// checks hold at most 38 MiB on a small host.
	maxHashing = 2
)

// throttle limits password guessing with two windows, per administrator name
// and per client address. Unknown names are counted like existing ones, so
// the answers never show which names exist. Counters are in memory: a restart
// clears them.
type throttle struct {
	mu      sync.Mutex
	names   map[string]*counter
	sources map[string]*counter
}

// counter holds the failures settled since start and the attempts still
// being checked. An attempt in progress counts against the limit, so
// concurrent attempts cannot all pass the check; a new window clears only
// settled failures, so attempts begun in the old one still count.
type counter struct {
	failures    int
	pending     int
	start       time.Time
	lockedUntil time.Time
}

// open reports whether another attempt may start, opening a new window when
// the last one has passed.
func (c *counter) open(now time.Time, limit int) bool {
	if now.Before(c.lockedUntil) {
		return false
	}
	if now.Sub(c.start) >= failureWindow {
		c.failures, c.start = 0, now
	}
	return c.failures+c.pending < limit
}

// settle ends one attempt in progress: a failure is counted and locks the
// counter at its limit; anything else leaves no trace.
func (c *counter) settle(failed bool, limit int, now time.Time) {
	c.pending = max(c.pending-1, 0)
	if !failed {
		return
	}
	c.failures++
	if c.failures+c.pending >= limit {
		c.failures, c.lockedUntil = 0, now.Add(lockoutPeriod)
	}
}

func newThrottle() *throttle {
	return &throttle{names: map[string]*counter{}, sources: map[string]*counter{}}
}

// attempt is one password or enrolment check that begin admitted.
type attempt struct {
	throttle     *throttle
	name, source string
}

// begin admits an attempt on name from the request's client address, or
// returns the refusal reason: "throttled" for the address or a full table,
// "locked" for the name.
func (t *throttle) begin(name string, r *http.Request, now time.Time) (attempt, string) {
	source := clientAddress(r)
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.names)+len(t.sources) >= maxEntries-1 {
		t.prune(now)
	}
	if len(t.names)+len(t.sources) >= maxEntries-1 {
		return attempt{}, "throttled"
	}
	byName, bySource := t.entry(t.names, nameKey(name)), t.entry(t.sources, source)
	if !bySource.open(now, maxSourceFailures) {
		return attempt{}, "throttled"
	}
	if !byName.open(now, maxNameFailures) {
		return attempt{}, "locked"
	}
	byName.pending++
	bySource.pending++
	return attempt{throttle: t, name: nameKey(name), source: source}, ""
}

// nameKey is the counter key for a name. Names no administrator can hold
// share one counter, so a sign-in body cannot store kilobytes per entry.
func nameKey(name string) string {
	if store.IsAdminName(name) {
		return name
	}
	return ""
}

func (t *throttle) entry(table map[string]*counter, key string) *counter {
	c := table[key]
	if c == nil {
		c = &counter{}
		table[key] = c
	}
	return c
}

// prune drops counters that are not locked, not inside a window and have
// no attempt in progress.
func (t *throttle) prune(now time.Time) {
	for _, table := range []map[string]*counter{t.names, t.sources} {
		for key, c := range table {
			if c.pending == 0 && !now.Before(c.lockedUntil) && now.Sub(c.start) >= failureWindow {
				delete(table, key)
			}
		}
	}
}

// failed settles the attempt as a wrong password or enrolment secret.
func (a attempt) failed(now time.Time) { a.settle(true, false, now) }

// succeeded settles a verified attempt: the name's failures are cleared.
func (a attempt) succeeded() { a.settle(false, true, time.Now()) }

// abandoned settles an attempt the gateway could not check.
func (a attempt) abandoned() { a.settle(false, false, time.Now()) }

func (a attempt) settle(failed, verified bool, now time.Time) {
	t := a.throttle
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.names[a.name]; c != nil {
		c.settle(failed, maxNameFailures, now)
		if verified {
			c.failures = 0
		}
	}
	if c := t.sources[a.source]; c != nil {
		c.settle(failed, maxSourceFailures, now)
	}
}

// clientAddress is the request's peer IP address. The Admin API listens on
// loopback only and trusts no forwarding header.
func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
