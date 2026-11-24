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
