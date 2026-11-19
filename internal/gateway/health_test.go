// The health listener: it serves /livez and /readyz alone, so readiness can
// reach a load balancer without /metrics, and it stays on loopback unless
// gateway.health_listen_any is set.

package gateway

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

func TestHealthListener(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	settings := e.NativeSettings()
	healthAddr := gatewaytest.FreeAddr(t)
	gatewaytest.Section(settings, "gateway")["health_listen"] = healthAddr
	e.WriteNative(settings)
	cfg, err := loadNativeConfig(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	g, err := startNative(cfg, slog.New(slog.NewJSONHandler(&gatewaytest.LogBuffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.stop() })
	status := func(address, path string) int {
		reply, err := http.Get("http://" + address + path)
		if err != nil {
			t.Fatal(err)
		}
		reply.Body.Close()
		return reply.StatusCode
	}
	for _, c := range []struct {
		address, path string
		want          int
	}{
		{healthAddr, "/livez", http.StatusOK},
		{healthAddr, "/readyz", http.StatusOK},
		{healthAddr, "/metrics", http.StatusNotFound},
		{cfg.metricsListen, "/readyz", http.StatusOK},
		{cfg.metricsListen, "/metrics", http.StatusOK},
	} {
		if got := status(c.address, c.path); got != c.want {
			t.Errorf("%s%s: %d, want %d", c.address, c.path, got, c.want)
		}
	}
	if checkHealth(e.Config, slog.New(slog.DiscardHandler)) != 0 {
		t.Error("the health command did not find the gateway ready through the health listener")
	}
}

func TestHealthListenLoopback(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	for name, c := range map[string]struct {
		any bool
		ok  bool
	}{"network health without switch": {false, false}, "network health with switch": {true, true}} {
		settings := e.NativeSettings()
		gatewaytest.Section(settings, "gateway")["health_listen"] = "0.0.0.0:9451"
		gatewaytest.Section(settings, "gateway")["health_listen_any"] = c.any
		e.WriteNative(settings)
		cfg, err := loadNativeConfig(e.Config)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if err != nil && !strings.Contains(err.Error(), "gateway.health_listen") {
			t.Errorf("%s: %v does not name the setting", name, err)
		}
		if err == nil && !strings.Contains(fmtWeakenings(cfg), "gateway.health_listen_any") {
			t.Errorf("%s: no warning names gateway.health_listen_any", name)
		}
	}
}

// fmtWeakenings joins the settings the weakening warnings name.
func fmtWeakenings(cfg nativeConfig) string {
	var names []string
	for _, w := range weakenings(cfg) {
		names = append(names, w.setting)
	}
	return strings.Join(names, " ")
}
