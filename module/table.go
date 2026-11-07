// The bounded keyed table a module keeps per-key state in.

package module

import "sync"

// Table holds per-key state for a module, bounded by a fixed number of keys.
// When it is full, Update refuses a new key instead of evicting one, so the
// module can fail closed. It is safe for concurrent use.
type Table[K comparable, V any] struct {
	mu      sync.Mutex
	max     int
	entries map[K]V
}

// NewTable returns an empty table holding at most max keys; max must be
// positive.
func NewTable[K comparable, V any](max int) *Table[K, V] {
	if max <= 0 {
		panic("module: a table needs a positive size")
	}
	return &Table[K, V]{max: max, entries: map[K]V{}}
}

// Update replaces key's value with change(current, found) as one atomic step.
// It returns false, changing nothing, when key is new and the table is full.
func (t *Table[K, V]) Update(key K, change func(current V, found bool) V) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	current, found := t.entries[key]
	if !found && len(t.entries) >= t.max {
		return false
	}
	t.entries[key] = change(current, found)
	return true
}

// Delete removes key.
func (t *Table[K, V]) Delete(key K) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// Len returns the number of keys held.
func (t *Table[K, V]) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}
