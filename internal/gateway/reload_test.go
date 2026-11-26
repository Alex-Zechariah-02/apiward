// The keys reload: the start's checks, and only reloadable settings applied.

package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
	if trust, _, _, _, err := reload(); err != nil || len(trust.Keys) != 2 {
		t.Fatalf("key list change: %v %v", trust.Keys, err)
	}

	save(func(_, d map[string]any) {
		d["listen"] = "127.0.0.3:9480"
		d["max_body_bytes"] = 1024
	})
	// Applied, with the restart-only settings named as a warning.
	if _, _, _, warnings, err := reload(); err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "only at a restart: data.listen, data.max_body_bytes") {
		t.Fatalf("restart-only change: %v %v", warnings, err)
	}

	save(func(map[string]any, map[string]any) {})
	moved := filepath.Join(dir, "moved.json")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Skipf("this host cannot create links: %v", err)
	}
	// A link to a regular file is read, as a container's mounted
	// configuration is.
	if _, _, _, _, err := reload(); err != nil {
		t.Fatalf("settings file behind a link: %v", err)
	}
}

// A reload reads the identity signing key too, so a damaged key file refuses
// the reload instead of switching to bad material.
func TestKeysReloadChecksIdentityKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "identity.pem")
	if err := os.WriteFile(identity, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.json")
	document := configDocument(t, dir, func(s map[string]any) { gatewaytest.Section(s, "upstream")["identity_key"] = identity })
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := settings.native.controller.ReloadKeys(); err == nil {
		t.Fatal("reload with a damaged identity key file succeeded, want refusal")
	}
}
