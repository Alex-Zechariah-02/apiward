// A library-mode call that arrives after Stop waited for the calls in
// progress is refused before it reaches the pipeline.

package gateway

import (
	"context"
	"testing"
)

func TestCallsRefusedAfterWait(t *testing.T) {
	t.Parallel()
	q := calls{idle: make(chan struct{}, 1)}
	if !q.enter() {
		t.Fatal("a call before the stop was refused")
	}
	q.leave()
	if err := q.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q.enter() {
		t.Fatal("a call after the wait entered the pipeline")
	}
	if q.active.Load() != 0 {
		t.Fatalf("a refused call stayed counted: %d", q.active.Load())
	}
}
