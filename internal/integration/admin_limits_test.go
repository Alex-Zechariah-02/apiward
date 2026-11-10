// Admin API limits read: each built-in limit with its current use.

package integration

import (
	"encoding/json"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// The limits read reports each built-in limit with its current use, taken
// from the component that owns it (configured ceilings included), and needs
// a signed-in administrator.
func TestAdminLimits(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	settings := e.NativeSettings()
	settings["limits"] = map[string]any{"rate_counters": 1000, "monitor_window": 500}
	e.WriteNative(settings)
	e.Start(gatewaytest.Binaries.Plain)
	if code, _, _ := e.AdminSend("GET", "/admin/limits", ""); code != 401 {
		t.Fatalf("limits without a session: %d", code)
	}
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	e.Get("/a/first")
	e.Get("/missing")
	code, body, _ := e.As(admin, "GET", "/admin/limits", "")
	if code != 200 {
		t.Fatalf("limits: %d %s", code, body)
	}
	var limits map[string]struct {
		Used int64 `json:"used"`
		Max  int64 `json:"max"`
	}
	if err := json.Unmarshal([]byte(body), &limits); err != nil || len(limits) != 7 {
		t.Fatalf("limits body: %s (%v)", body, err)
	}
	want := map[string]int64{
		"temporary_rules": store.MaxActiveOverrides, "live_views": monitor.MaxStreams, "administrator_sessions": session.Max,
		"rate_counters": 1000, "recent_requests": 500,
	}
	for name, max := range want {
		if limits[name].Max != max {
			t.Errorf("%s max = %d, want %d", name, limits[name].Max, max)
		}
	}
	if got := limits["administrator_sessions"].Used; got < 1 {
		t.Errorf("sessions used = %d, want the signed-in administrator", got)
	}
	if got := limits["recent_requests"].Used; got < 2 {
		t.Errorf("recent requests used = %d, want the two requests sent", got)
	}
	if got := limits["temporary_rules"].Used; got != 0 {
		t.Errorf("temporary rules used = %d, want 0", got)
	}
	if files, bytes := limits["audit_files"], limits["audit_active_bytes"]; files.Used < 1 || files.Used > files.Max || bytes.Used < 1 || bytes.Used > bytes.Max {
		t.Errorf("audit usage: files %+v, active bytes %+v", files, bytes)
	}
}
