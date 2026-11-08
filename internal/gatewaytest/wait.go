// Waiting for a condition with a deadline, and a process output buffer
// readable while the process writes it.

package gatewaytest

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// WaitFor polls cond until it holds or the limit passes.
func WaitFor(t *testing.T, limit time.Time, what string, cond func() bool) {
	t.Helper()
	for !cond() {
		if time.Now().After(limit) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// LogBuffer collects a controller's log output.
type LogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends p; the process writes its output here.
func (b *LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String is everything written so far.
func (b *LogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
