// The window of recent requests and the live views that follow it.

package monitor

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// QueueSize events buffer a burst for one live view; a view that falls
// further behind is told how many it missed, so a slow reader never slows
// request recording.
const QueueSize = 128

// MaxStreams live views may be open: each holds a queue and a response
// writer, and eight cover a small team's open tabs.
const MaxStreams = 8

type Viewer struct {
	events  chan Entry
	dropped atomic.Uint64
}

// Observations owns a bounded ring and bounded, nonblocking subscriptions.
// It has no authority over admission, policy, durable audit or upstream writes.
type Observations struct {
	// mu guards the ring and the viewers. A request holds it only to store
	// its entry and hand it to the live views.
	mu      sync.Mutex
	ring    ring
	viewers map[*Viewer]bool
	// newest is the latest request time recorded and late the most any
	// request was recorded behind it, which bounds how far a time-bounded
	// walk must look past its start (see Walk).
	newest  time.Time
	late    time.Duration
	dropped atomic.Uint64
	done    chan struct{}
	closed  bool
	metrics requestMetrics
	permits permitTracker
	// redirects counts the redirect listener's 308 answers, refused the
	// data connections closed at the connection cap, and auxiliary the
	// connections each other listener closed at its cap (by AuxiliaryListener);
	// they need no lock.
	redirects atomic.Uint64
	refused   atomic.Uint64
	// http2 counts the data listener's HTTP/2 protocol errors.
	http2     atomic.Uint64
	auxiliary [auxiliaryListeners]atomic.Uint64
	// admin counts the Admin API's own failures by AdminFailure.
	admin [adminFailures]atomic.Uint64
	// keyReloads counts key reloads refused because the keys or the
	// settings beside them were invalid.
	keyReloads atomic.Uint64
}

// New keeps the last window requests; apis bounds the per-API duration
// metrics. Both are the resolved capacity limits.
func New(window, apis int) *Observations {
	return &Observations{ring: ring{size: window}, viewers: map[*Viewer]bool{}, done: make(chan struct{}), metrics: requestMetrics{apis: apis}}
}

// Record keeps a request's final event in the window, counts it in the
// metrics and hands it to the live views. The view is built only when read.
func (o *Observations) Record(event audit.Event) {
	entry := newEntry(event)
	o.metrics.Record(event)
	o.permits.record(event)
	// One lock keeps the window and the live feeds consistent with each other.
	o.mu.Lock()
	defer o.mu.Unlock()
	if entry.Time.After(o.newest) {
		o.newest = entry.Time
	} else if late := o.newest.Sub(entry.Time); late > o.late {
		o.late = late
	}
	stored := o.ring.push(entry)
	for viewer := range o.viewers {
		select {
		case viewer.events <- *stored:
		default:
			viewer.dropped.Add(1)
			o.dropped.Add(1)
		}
	}
}

func (o *Observations) Subscribe() *Viewer {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || len(o.viewers) >= MaxStreams {
		return nil
	}
	viewer := &Viewer{events: make(chan Entry, QueueSize)}
	o.viewers[viewer] = true
	return viewer
}

func (o *Observations) Unsubscribe(viewer *Viewer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.viewers, viewer)
}

// TakeDropped returns and resets the count of requests the viewer missed.
func (o *Observations) TakeDropped(viewer *Viewer) uint64 { return viewer.dropped.Swap(0) }

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
	return o.ring.count
}

// Window returns the number of requests the window keeps at most.
func (o *Observations) Window() int { return o.ring.size }

// Feed delivers the viewer's requests.
func (v *Viewer) Feed() <-chan Entry { return v.events }

// Closing closes when the observations close.
func (o *Observations) Closing() <-chan struct{} { return o.done }
