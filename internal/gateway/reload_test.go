// The keys reload: the start's checks, and only reloadable settings applied.

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// A reload takes a changed key list; a changed restart-only setting is
// refused by name, and a file that is no longer a regular file is refused as
// at start.
func TestKeysReloadScope(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	save := func(change func(gateway, data map[string]any)) {
		t.Helper()
		document := configDocument(t, dir, func(s map[string]any) {
			gatewaytest.Section(s, "upstream")["unsigned_identity"] = true
			change(gatewaytest.Section(s, "gateway"), gatewaytest.Section(s, "data"))
		})
		if err := os.WriteFile(path, document, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	save(func(map[string]any, map[string]any) {})
	settings, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	reload := settings.native.controller.ReloadKeys

	save(func(g, _ map[string]any) {
		jwt := g["jwt"].(map[string]any)
		jwt["keys"] = append(jwt["keys"].([]pipeline.VerificationKey), pipeline.VerificationKey{Kid: "test-b", PublicKeyFile: filepath.Join(dir, "second.pem")})
	})
	if trust, _, err := reload(); err != nil || len(trust.Keys) != 2 {
		t.Fatalf("key list change: %v %v", trust.Keys, err)
	}

	save(func(_, d map[string]any) {
		d["listen"] = "127.0.0.3:9480"
		d["max_body_bytes"] = 1024
	})
	if _, _, err := reload(); err == nil || !strings.Contains(err.Error(), "only at a restart: data.listen, data.max_body_bytes") {
		t.Fatalf("restart-only change: %v", err)
	}

	save(func(map[string]any, map[string]any) {})
	moved := filepath.Join(dir, "moved.json")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Skipf("this host cannot create links: %v", err)
	}
	if _, _, err := reload(); err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("settings file replaced by a link: %v", err)
	}
}
