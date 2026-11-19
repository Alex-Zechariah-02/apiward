// Benchmarks of the controller's control-plane paths: a mutation's checks,
// the read-only capture and compiling an effective generation.

package controller

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

func benchController(b *testing.B) *Controller {
	b.Helper()
	e := newEnv(b)
	storetest.Seed(b, e.database, storetest.Protected(), storetest.Options{})
	c := e.own(e.controllerConfig())
	if c.Current() == nil {
		b.Fatalf("nothing published: %v", c.State())
	}
	return c
}

func BenchmarkValidateOverride(b *testing.B) {
	c := benchController(b)
	request := permitOverride(store.OverrideException, "READER", "write-a", 60)
	b.ReportAllocs()
	for b.Loop() {
		if result, status := c.ValidateOverride(context.Background(), "admin", 1, request); status != http.StatusOK {
			b.Fatalf("%d %+v", status, result)
		}
	}
}

func BenchmarkCapture(b *testing.B) {
	c := benchController(b)
	b.ReportAllocs()
	for b.Loop() {
		if g, _, err := c.Capture(context.Background()); g == nil || err != nil {
			b.Fatal(g, err)
		}
	}
}

func BenchmarkEffectiveGeneration(b *testing.B) {
	base := storetest.Protected()
	base.Operations[0].Rate = storetest.Rate(4, 60)
	expires := time.Now().Add(time.Hour)
	overrides := []store.Override{
		{ID: 3, Type: store.OverrideException, Control: store.ControlPermit, Role: "READER", Operation: "write-a", Target: "permit:READER:write-a", ExpiresAt: expires},
		{ID: 5, Type: store.OverrideException, Control: store.ControlRate, Operation: "read-a", Count: 9, Target: "rate:read-a", ExpiresAt: expires},
	}
	network := closedNetwork(&testing.T{})
	b.ReportAllocs()
	for b.Loop() {
		unlabelled, err := effectiveGeneration(network, base, 0, time.Time{}, overrides, policy.Limits{})
		if err != nil {
			b.Fatal(err)
		}
		unlabelled.Relabel(7, unlabelled.Overrides)
	}
}
