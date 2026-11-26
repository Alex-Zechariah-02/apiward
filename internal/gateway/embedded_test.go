// Settings rejected by library mode because the host owns the data listener.

package gateway

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// Library mode refuses data.max_connections_per_address by name, since the
// host program owns the data listener.
func TestEmbeddedRefusesPerAddressCap(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	native := e.NativeSettings()
	gatewaytest.Section(native, "data")["max_connections_per_address"] = 10
	e.WriteNative(native)
	hosted, err := LoadSettings(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(&gatewaytest.LogBuffer{}, nil))
	if lib, err := OpenEmbedded(hosted, logger); !slices.Equal(kinds(err), []error{ErrConfig}) || !strings.Contains(err.Error(), "data.max_connections_per_address") {
		if lib != nil {
			lib.Stop(context.Background())
		}
		t.Fatalf("per-address cap for a host's server: %v", err)
	}
}

func TestCallsStateLifecycle(t *testing.T) {
	t.Parallel()
	q := calls{idle: make(chan struct{}, 1)}
	if !q.enter() {
		t.Fatal("enter refused while open")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := q.wait(cancelled); err == nil {
		t.Fatal("wait succeeded with an active call and cancelled context")
	}
	if callsState(q.state.Load()) != callsDraining {
		t.Fatalf("state after cancelled drain = %d, want callsDraining", q.state.Load())
	}
	done := make(chan error, 1)
	go func() { done <- q.wait(context.Background()) }()
	q.leave()
	if err := <-done; err != nil {
		t.Fatalf("wait after leave: %v", err)
	}
	if callsState(q.state.Load()) != callsClosed {
		t.Fatalf("state after wait = %d, want callsClosed", q.state.Load())
	}
	if q.enter() || q.active.Load() != 0 {
		t.Fatalf("enter after close succeeded or leaked active count %d", q.active.Load())
	}
}
