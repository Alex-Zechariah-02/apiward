// Upstream fast-fail: an endpoint that refuses connections repeatedly is
// ejected for a while, so requests to it fail at once instead of each
// waiting for a dial to fail.

package forward

import (
	"errors"
	"sync"
	"time"
)

// errEjected refuses a request to an ejected endpoint; it was never sent.
var errEjected = errors.New("upstream ejected after repeated connection failures")

// The first ejection lasts ejectFirst; each repeated one doubles it, up to
// ejectLongest (Envoy outlier detection's base and maximum ejection times
// are 30 s and 300 s; a gateway in front of a few upstreams returns sooner).
const (
	ejectFirst   = time.Second
	ejectLongest = 30 * time.Second
)

// ejector counts consecutive connection failures per endpoint address. After
// `after` of them the endpoint is ejected: requests to it fail at once until
// the ejection time has passed; then one request probes it while the others
// still fail. A connection that succeeds resets the endpoint; a failed probe
// ejects it again for twice as long. Requests are never resent.
type ejector struct {
	after int // 0: never eject
	mu    sync.Mutex
	// states holds only endpoints with a failure since their last success,
	// so it is bounded by the policy's endpoints that are failing.
	states map[string]*ejection
}

type ejection struct {
	failures int
	until    time.Time     // zero while not ejected
	wait     time.Duration // the last ejection's length
	probing  bool          // the one request allowed after until is in flight
}

func newEjector(after int) *ejector {
	return &ejector{after: after, states: map[string]*ejection{}}
}

// admit reports whether a request may be sent to address at now.
func (e *ejector) admit(address string, now time.Time) bool {
	if e.after == 0 {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.states[address]
	if s == nil || s.until.IsZero() {
		return true
	}
	if now.Before(s.until) || s.probing {
		return false
	}
	s.probing = true
	return true
}

// result records whether a request admitted to address could connect.
func (e *ejector) result(address string, connected bool, now time.Time) {
	if e.after == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if connected {
		delete(e.states, address)
		return
	}
	s := e.states[address]
	if s == nil {
		s = &ejection{}
		e.states[address] = s
	}
	// Requests sent before the ejection began may still fail during it;
	// they neither extend nor repeat it.
	if now.Before(s.until) {
		return
	}
	s.failures++
	if !s.probing && s.failures < e.after {
		return
	}
	s.wait = min(max(2*s.wait, ejectFirst), ejectLongest)
	s.until, s.probing = now.Add(s.wait), false
}

// settle records how a request admitted to address ended. A request whose
// client went away before any connection was made says nothing about the
// endpoint; it only passes a probe's turn to the next request.
func (e *ejector) settle(address string, connected, clientGone bool) {
	if !connected && clientGone {
		e.release(address)
		return
	}
	e.result(address, connected, time.Now())
}

// release passes a probe's turn on address to the next request.
func (e *ejector) release(address string) {
	if e.after == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if s := e.states[address]; s != nil {
		s.probing = false
	}
}
