// Recovery retries of the stored authority: one at a time, and only for a
// state a later read can clear.

package controller

import (
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

// A state no retry clears arms nothing, and a pending retry is not replaced
// or its pause doubled by another request for one.
func TestScheduleRetryArmsOnce(t *testing.T) {
	e := newEnv(t)
	storetest.Seed(t, e.database, storetest.Protected(), storetest.Options{})
	c := e.own(e.controllerConfig())
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scheduleRetry("policy_invalid")
	if c.retry != nil {
		t.Fatal("a retry armed for a state no retry clears")
	}
	c.scheduleRetry("store_unavailable")
	first, pause := c.retry, c.retryWait
	if first == nil {
		t.Fatal("no retry armed for an unavailable store")
	}
	c.scheduleRetry("store_unavailable")
	if c.retry != first || c.retryWait != pause {
		t.Fatalf("a second request replaced the pending retry (pause %v, then %v)", pause, c.retryWait)
	}
	c.stopRetry()
}
