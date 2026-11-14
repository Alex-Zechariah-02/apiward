// Reads of the window of recent requests: copies and walks that hold the
// lock the request path records under for at most one batch at a time.

package monitor

import "time"

// Recent returns, newest first, the retained requests that keep accepts,
// stopping once it has limit of them (0: no limit). Only returned requests
// are copied, so a reader that wants a short window or a few matches does
// not copy the whole ring while holding the lock the request path records
// under. keep runs under that lock and must not block.
func (o *Observations) Recent(keep func(*Observed) bool, limit int) []Observed {
	var result []Observed
	o.walk(func(request *Observed) bool {
		if keep(request) {
			result = append(result, *request)
		}
		return len(result) != limit
	})
	return result
}

// readBatch bounds how many retained requests a reader visits per hold of
// the lock, so a request recording waits at most one batch, not a whole
// ring (up to 100,000 requests).
const readBatch = 256

// walk visits, newest first, the requests retained when it starts, until
// visit returns false. It releases the lock between batches; a request the
// ring drops meanwhile is skipped, one recorded meanwhile is not visited.
// visit runs under the lock and must not block.
func (o *Observations) walk(visit func(*Observed) bool) {
	o.mu.Lock()
	newest, oldest := o.next, o.next-uint64(len(o.ring)) // #nosec G115 -- the ring never holds more than next requests
	o.mu.Unlock()
	for sequence := newest; sequence > oldest; {
		o.mu.Lock()
		retained := o.next - uint64(len(o.ring)) // #nosec G115 -- as above
		for end := sequence - min(sequence-oldest, readBatch); sequence > end; sequence-- {
			if sequence <= retained {
				o.mu.Unlock()
				return
			}
			if !visit(&o.ring[(sequence-1)%uint64(o.window)]) { // #nosec G115 -- the window is a validated positive size
				o.mu.Unlock()
				return
			}
		}
		o.mu.Unlock()
	}
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

// Snapshot copies, newest first, the requests retained when it starts, in
// batches (see walk), so the request path never waits for a whole-ring copy.
func (o *Observations) Snapshot() []Observed {
	o.mu.Lock()
	result := make([]Observed, 0, len(o.ring))
	o.mu.Unlock()
	o.walk(func(request *Observed) bool {
		result = append(result, *request)
		return true
	})
	return result
}
