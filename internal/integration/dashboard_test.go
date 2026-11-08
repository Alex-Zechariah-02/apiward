// The dashboard setting: without it no page is served, and a setting naming
// no dashboard stops startup.

package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// Without the setting the admin listener serves no page, and a setting that
// names no dashboard stops startup instead of serving an empty origin.
func TestDashboardSetting(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	for _, p := range []string{"/", "/assets/app.js"} {
		if code, _, _ := e.AdminSend(http.MethodGet, p, ""); code != http.StatusNotFound {
			t.Errorf("GET %s without admin_ui: %d", p, code)
		}
	}
	e.Stop()

	empty := t.TempDir()
	notDirectory := filepath.Join(empty, "index.html")
	if err := os.WriteFile(notDirectory, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{
		"missing directory": filepath.Join(empty, "absent"),
		"no index page":     t.TempDir(),
		"a file":            notDirectory,
	} {
		e.WriteConfig(gatewaytest.ConfigOptions{Admin: map[string]any{"admin_ui": dir}})
		e.Launch(gatewaytest.Binaries.Plain, []string{"run", "--config", e.Config})
		if code := e.WaitExit(); code == 0 || !strings.Contains(e.Output.String(), "admin_ui") {
			t.Errorf("%s: exit %d\n%s", name, code, e.Output)
		}
	}
}
