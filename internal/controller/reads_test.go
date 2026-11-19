// The read-only capture of the generation and stored authority.

package controller

import (
	"context"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

// A read-only capture does not wait for the mutation lock while nothing
// changes, so an impact preview never queues behind a publication.
func TestCaptureWithoutLock(t *testing.T) {
	e := newEnv(t)
	storetest.Seed(t, e.database, storetest.Protected(), storetest.Options{})
	c := e.own(e.controllerConfig())
	c.mu.Lock()
	defer c.mu.Unlock()
	captured := make(chan error, 1)
	go func() {
		g, a, err := c.Capture(context.Background())
		if err == nil && (g == nil || a.Revision != g.Revision) {
			t.Errorf("captured %v with revision %d", g, a.Revision)
		}
		captured <- err
	}()
	select {
	case err := <-captured:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the capture waited for the mutation lock")
	}
}
