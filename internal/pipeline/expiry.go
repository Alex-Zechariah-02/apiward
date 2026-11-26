// Typed min-heap of rate counters ordered by removable time, so sweeps visit
// only counters they remove without interface boxing or unchecked assertions.

package pipeline

// expiryQueue orders counters by the time they become removable.
type expiryQueue []*counter

func (q expiryQueue) swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index, q[j].index = i, j
}

func (q *expiryQueue) push(c *counter) {
	c.index = len(*q)
	*q = append(*q, c)
	q.up(c.index)
}

func (q *expiryQueue) pop() *counter {
	old := *q
	top := old[0]
	last := len(old) - 1
	q.swap(0, last)
	old[last] = nil
	*q = old[:last]
	if len(*q) > 0 {
		q.down(0)
	}
	return top
}

func (q expiryQueue) fix(i int) {
	if !q.down(i) {
		q.up(i)
	}
}

func (q expiryQueue) up(i int) {
	for i > 0 {
		parent := (i - 1) / 2
		if q[i].removable() >= q[parent].removable() {
			break
		}
		q.swap(i, parent)
		i = parent
	}
}

func (q expiryQueue) down(i int) bool {
	start := i
	for {
		left := 2*i + 1
		if left >= len(q) {
			break
		}
		smallest := left
		if right := left + 1; right < len(q) && q[right].removable() < q[left].removable() {
			smallest = right
		}
		if q[i].removable() <= q[smallest].removable() {
			break
		}
		q.swap(i, smallest)
		i = smallest
	}
	return i > start
}
