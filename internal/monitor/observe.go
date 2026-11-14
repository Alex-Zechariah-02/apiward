// The window of recent requests and the live views that follow it.

package monitor

import (
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

const QueueSize = 128
const MaxStreams = 8

// RequestView is the explicit, secret-free Admin API projection. Private audit
// envelopes and their future fields are never serialized to viewers.
type RequestView struct {
	RequestID     string    `json:"request_id"`
	Time          time.Time `json:"time"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	Operation     *string   `json:"operation"`
	API           *string   `json:"api"`
	Subject       *string   `json:"subject"`
	Roles         []string  `json:"roles"`
	ClientAddress string    `json:"client_address"`
	Decision      string    `json:"decision"`
	Status        int       `json:"status"`
	Stage         string    `json:"stage"`
	Code          *string   `json:"code"`
	Generation    string    `json:"generation"`
	DurationMS    float64   `json:"duration_ms"`
	// Modules is present only in builds with modules other than the built-ins.
	Modules map[string]string `json:"modules,omitempty"`
}

type Observed struct {
	RequestView
	sequence      uint64
	assertedRoles []string // verified assertions, including roles dropped by the active policy
	identityKnown bool     // evaluated authentication, or no credential was supplied
	// routingPath is separate from the displayed path. One byte beyond the
	// longest target distinguishes an exact match from a longer request; prefix
	// matching needs no more. Empty means canonicalization did not pass.
	routingPath string
}

type Viewer struct {
	events  chan Observed
	dropped uint64 // guarded by observations.mu
}

// Observations owns a bounded ring and bounded, nonblocking subscriptions.
// It has no authority over admission, policy, durable audit or upstream writes.
type Observations struct {
	mu sync.Mutex
	// ring grows to window requests as they arrive, then the newest replaces
	// the oldest, so an idle gateway holds no window it has not used.
	ring    []Observed
	window  int
	next    uint64
	viewers map[*Viewer]bool
	dropped uint64
	done    chan struct{}
	closed  bool
	metrics requestMetrics
	// redirects counts the redirect listener's 308 answers, refused the
	// data connections closed at the connection cap, and auxiliary the
	// connections each other listener closed at its cap (keys fixed by New);
	// they need no lock.
	redirects atomic.Uint64
	refused   atomic.Uint64
	auxiliary map[string]*atomic.Uint64
}

// New keeps the last window requests; apis bounds the per-API duration
// metrics. Both are the resolved capacity limits.
func New(window, apis int) *Observations {
	o := &Observations{window: window, viewers: map[*Viewer]bool{}, done: make(chan struct{}), metrics: requestMetrics{apis: apis},
		auxiliary: map[string]*atomic.Uint64{}}
	for _, name := range Auxiliary {
		o.auxiliary[name] = new(atomic.Uint64)
	}
	return o
}

func OptionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// View is the secret-free view of a request's final audit event, shared
// by the live views and the security log search so both show the same fields.
func View(event audit.Event) RequestView {
	view := RequestView{
		RequestID: event.RequestID, Time: event.Time, Method: event.Method,
		Path:      strings.Clone(event.Path[:min(len(event.Path), audit.MaxLoggedPath)]),
		Operation: OptionalString(event.Operation), API: OptionalString(event.API), Subject: OptionalString(event.Subject),
		Roles: slices.Clone(event.Roles), ClientAddress: event.ClientAddress, Status: event.Status,
		Code: OptionalString(event.Error), Generation: event.Generation, DurationMS: event.DurationMS,
		Modules: maps.Clone(event.Modules),
	}
	if view.Roles == nil {
		view.Roles = []string{}
	}
	switch event.Decision {
	case "forwarded", "allowed": // allowed: a CORS preflight the gateway answered
		view.Decision = "allowed"
	case "upstream_failure":
		view.Decision = "failed"
	default:
		view.Decision = "refused"
	}
	switch event.Stage {
	case "FORWARD", "BIND":
		view.Stage = "forward"
	case "ACCESS":
		view.Stage = "access"
	case "JWT":
		view.Stage = "token"
	case "RBAC":
		view.Stage = "permit"
		if event.Error == "account_blocked" {
			view.Stage = "blocked"
		}
	case "RATE":
		view.Stage = "rate"
	case "BODY", "VALIDATION", "INGRESS", "CANONICAL":
		view.Stage = "validation"
	case "AUDIT", "CAPTURE":
		view.Stage = "record"
	default:
		view.Stage = "route"
	}
	return view
}

func (o *Observations) Record(event audit.Event) {
	view := View(event)
	var routingPath string
	if event.Stages[audit.StageCanonical] == audit.StagePass {
		routingPath = strings.Clone(event.Path[:min(len(event.Path), policy.MaxTargetLength+1)])
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.metrics.Record(view)
	o.next++
	asserted := append(slices.Clone(view.Roles), event.IgnoredRoles...)
	slices.Sort(asserted)
	request := Observed{RequestView: view, sequence: o.next, assertedRoles: asserted, identityKnown: event.IdentityKnown(), routingPath: routingPath}
	if len(o.ring) < o.window {
		// Grown by hand: append's growth could overshoot the window.
		if len(o.ring) == cap(o.ring) {
			o.ring = append(make([]Observed, 0, min(max(2*cap(o.ring), 64), o.window)), o.ring...)
		}
		o.ring = append(o.ring, request)
	} else {
		o.ring[o.slot(0)] = request
	}
	for viewer := range o.viewers {
		select {
		case viewer.events <- request:
		default:
			viewer.dropped++
			o.dropped++
		}
	}
}

// Recent returns, newest first, the retained requests that keep accepts,
// stopping once it has limit of them (0: no limit). Only returned requests
// are copied, so a reader that wants a short window or a few matches does
// not copy the whole ring while holding the lock the request path records
// under. keep runs under that lock and must not block.
func (o *Observations) Recent(keep func(*Observed) bool, limit int) []Observed {
	o.mu.Lock()
	defer o.mu.Unlock()
	var result []Observed
	for i := range len(o.ring) {
		request := &o.ring[o.slot(i)]
		if !keep(request) {
			continue
		}
		result = append(result, *request)
		if len(result) == limit {
			break
		}
	}
	return result
}

// RetainedSince returns the time of the oldest request still kept and
// whether older requests have already been dropped from the ring.
func (o *Observations) RetainedSince() (time.Time, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.ring) == 0 {
		return time.Time{}, false
	}
	return o.ring[o.slot(len(o.ring)-1)].Time, o.next > uint64(o.window) // #nosec G115 -- the window is a validated positive size
}

// slot is the ring index of the request age places before the newest. While
// the ring grows, request n sits at index n-1, which the modulus keeps.
func (o *Observations) slot(age int) uint64 {
	return (o.next - 1 - uint64(age)) % uint64(o.window) // #nosec G115 -- age is an index into the ring, never negative
}

func (o *Observations) Snapshot() []Observed {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make([]Observed, len(o.ring))
	for i := range result {
		result[i] = o.ring[o.slot(i)]
	}
	return result
}

func (o *Observations) Subscribe() *Viewer {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || len(o.viewers) >= MaxStreams {
		return nil
	}
	viewer := &Viewer{events: make(chan Observed, QueueSize)}
	o.viewers[viewer] = true
	return viewer
}

func (o *Observations) Unsubscribe(viewer *Viewer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.viewers, viewer)
}

func (o *Observations) TakeDropped(viewer *Viewer) uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	count := viewer.dropped
	viewer.dropped = 0
	return count
}

func (o *Observations) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.closed {
		o.closed = true
		close(o.done)
	}
}

// Viewers returns the number of open live views.
func (o *Observations) Viewers() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.viewers)
}

// Retained returns the number of requests kept in the window.
func (o *Observations) Retained() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.ring)
}

// Window returns the number of requests the window keeps at most.
func (o *Observations) Window() int { return o.window }

// Sequence is the request's position in the window, for paging.
func (e Observed) Sequence() uint64 { return e.sequence }

// ClaimedRoles are the verified role assertions, including roles the active
// policy dropped.
func (e Observed) ClaimedRoles() []string { return e.assertedRoles }

// Feed delivers the viewer's requests.
func (v *Viewer) Feed() <-chan Observed { return v.events }

// Closing closes when the observations close.
func (o *Observations) Closing() <-chan struct{} { return o.done }
