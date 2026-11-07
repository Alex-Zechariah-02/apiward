// The bounded window of recent requests and live viewers.

package monitor

import (
	"fmt"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

func TestFetchBoundedEventWindow(t *testing.T) {
	o := New()
	viewer := o.Subscribe()
	for i := range RecentLimit + 7 {
		o.Record(audit.Event{RequestID: fmt.Sprint(i), Decision: "reject", Stage: "ROUTE"})
	}
	events := o.Snapshot()
	if len(events) != 10000 || events[0].RequestID != "10006" || events[9999].RequestID != "7" {
		t.Fatalf("window bounds: %d %s %s", len(events), events[0].RequestID, events[len(events)-1].RequestID)
	}
	if dropped := o.TakeDropped(viewer); dropped != RecentLimit+7-QueueSize {
		t.Errorf("dropped %d", dropped)
	}
	if o.TakeDropped(viewer) != 0 {
		t.Fatal("drop count was not consumed")
	}
	o.Unsubscribe(viewer)
	o.Close()
	if o.Subscribe() != nil {
		t.Fatal("subscribed after shutdown")
	}
}
