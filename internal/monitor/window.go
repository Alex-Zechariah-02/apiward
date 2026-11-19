// The window of recent requests: a ring stored in blocks, and the walks
// that read it while holding the lock the request path records under for at
// most one batch copy at a time.

package monitor

import "time"

// blockShift sizes a ring block (256 entries): the ring grows a block at a
// time as requests arrive, so an idle gateway holds no window it has not
// used, and growing never copies the entries already kept.
const (
	blockShift = 8
	blockSize  = 1 << blockShift
	blockMask  = blockSize - 1
)

// ring keeps the last size entries. head is the slot the next entry goes
// into; slots advance by one and wrap at size, so no index needs a division.
type ring struct {
	blocks [][]Entry
	size   int
	count  int
	head   int
	next   uint64 // the sequence of the newest entry
}

func (r *ring) at(slot int) *Entry { return &r.blocks[slot>>blockShift][slot&blockMask] }

// push stores e as the newest entry and returns where it is kept.
func (r *ring) push(e Entry) *Entry {
	if r.head>>blockShift == len(r.blocks) {
		r.blocks = append(r.blocks, make([]Entry, min(blockSize, r.size-r.head)))
	}
	r.next++
	e.sequence = r.next
	slot := r.at(r.head)
	*slot = e
	r.head++
	if r.head == r.size {
		r.head = 0
	}
	r.count = min(r.count+1, r.size)
	return slot
}

// slot is the ring slot of the entry with sequence, which must be retained.
func (r *ring) slot(sequence uint64) int {
	s := r.head - 1 - int(r.next-sequence) // #nosec G115 -- a retained entry is less than size behind next
	if s < 0 {
		s += r.size
	}
	return s
}

// readBatch bounds how many retained requests a reader copies per hold of
// the lock, so a request recording waits at most one batch copy, not a
// whole ring (up to 100,000 requests).
const readBatch = 256

// Walk visits, newest first, the requests retained when it starts, until
// visit returns false. A non-zero from ends the walk once no request at or
// after from can follow: requests are kept in the order they ended, and none
// was recorded more than late behind a newer one, so once a request older
// than from minus late is seen, every earlier one is older than from too.
// Requests before from may still be visited; visit filters. Entries are
// copied in batches and visited outside the lock; a request the ring drops
// meanwhile is skipped, one recorded meanwhile is not visited. The entry
// is valid only during visit.
func (o *Observations) Walk(from time.Time, visit func(*Entry) bool) {
	o.walk(from, nil, visit)
}

// walk is Walk that copies only the entries keep accepts (nil: all); keep
// runs under the lock the request path records under and must not block.
func (o *Observations) walk(from time.Time, keep func(*Entry) bool, visit func(*Entry) bool) {
	batch := make([]Entry, 0, readBatch)
	o.mu.Lock()
	sequence := o.ring.next
	o.mu.Unlock()
	for ended := false; !ended; {
		o.mu.Lock()
		oldest := o.ring.next - uint64(o.ring.count) // #nosec G115 -- the ring never holds more than next requests
		horizon := from.Add(-o.late)
		batch = batch[:0]
		ended = sequence <= oldest
		if !ended {
			slot := o.ring.slot(sequence)
			for read := 0; read < readBatch; read++ {
				entry := o.ring.at(slot)
				if !from.IsZero() && entry.Time.Before(horizon) {
					ended = true
					break
				}
				if keep == nil || keep(entry) {
					batch = append(batch, *entry)
				}
				if sequence--; sequence <= oldest {
					ended = true
					break
				}
				if slot--; slot < 0 {
					slot = o.ring.size - 1
				}
			}
		}
		o.mu.Unlock()
		for i := range batch {
			if !visit(&batch[i]) {
				return
			}
		}
	}
}

// Recent returns, newest first, the retained requests that keep accepts,
// stopping once it has limit of them (0: no limit). Only returned requests
// are copied and projected; keep runs under the lock the request path
// records under and must not block.
func (o *Observations) Recent(keep func(*Entry) bool, limit int) []Observed {
	var result []Observed
	o.walk(time.Time{}, keep, func(e *Entry) bool {
		result = append(result, e.observed())
		return limit == 0 || len(result) < limit
	})
	return result
}

// Snapshot projects, newest first, the requests retained when it starts.
func (o *Observations) Snapshot() []Observed {
	result := make([]Observed, 0, o.Retained())
	o.Walk(time.Time{}, func(e *Entry) bool {
		result = append(result, e.observed())
		return true
	})
	return result
}

// RetainedSince returns the time of the oldest request still kept and
// whether older requests have already been dropped from the ring.
func (o *Observations) RetainedSince() (time.Time, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ring.count == 0 {
		return time.Time{}, false
	}
	oldest := o.ring.next - uint64(o.ring.count) + 1                              // #nosec G115 -- as in Walk
	return o.ring.at(o.ring.slot(oldest)).Time, o.ring.next > uint64(o.ring.size) // #nosec G115 -- the window is a validated positive size
}
