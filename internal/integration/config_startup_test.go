// Startup refuses invalid configuration.

package integration

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// legacyCaddyFile is e's deployment as the retired Caddy-hosted gateway was
// configured: its settings under apps.gateway and a data server under
// apps.http.
func legacyCaddyFile(e *gatewaytest.Env) []byte {
	return gatewaytest.MustJSON(map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{
			"gateway": gatewaytest.Section(e.NativeSettings(), "gateway"),
			"http":    map[string]any{"servers": map[string]any{"data": map[string]any{"listen": []string{e.DataAddr}}}},
		},
	})
}

// The native process refuses a configuration it cannot trust before it opens
// anything of the deployment: it exits with status 1 and a message naming the
// problem, no listener opens, no audit file is created and the database is
// left free for another owner. The controller's own checks (the admin
// address, the trust key, the dashboard directory) are refused the same way.
func TestNativeStartupRefusesConfiguration(t *testing.T) {
	privateKey := filepath.Join(t.TempDir(), "private.pem")
	der, _ := x509.MarshalPKCS8PrivateKey(issuertest.New(2048).Key())
	if err := os.WriteFile(privateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		write func(e *gatewaytest.Env)
		cause string
	}{
		{"malformed JSON", func(e *gatewaytest.Env) { e.WriteNativeFile([]byte(`{"version":1,"gateway":{`)) }, "not valid JSON"},
		{"repeated member", func(e *gatewaytest.Env) {
			document, _ := json.Marshal(e.NativeSettings())
			e.WriteNativeFile([]byte(strings.Replace(string(document), `"version":1`, `"version":1,"version":1`, 1)))
		}, "is repeated"},
		{"trailing content", func(e *gatewaytest.Env) {
			document, _ := json.Marshal(e.NativeSettings())
			e.WriteNativeFile(append(document, []byte(`{"version":1}`)...))
		}, "data after the JSON value"},
		{"unknown setting", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			gatewaytest.Section(s, "gateway")["audit_delete_oldest"] = true
			e.WriteNative(s)
		}, `unknown field \"audit_delete_oldest\"`},
		{"wrong type", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			gatewaytest.Section(s, "data")["max_body_bytes"] = "large"
			e.WriteNative(s)
		}, "data.max_body_bytes"},
		{"missing database", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			delete(gatewaytest.Section(s, "gateway"), "database")
			e.WriteNative(s)
		}, "gateway.database is required"},
		{"unsupported version", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			s["version"] = 0
			e.WriteNative(s)
		}, "version must be 1"},
		{"legacy Caddy configuration", func(e *gatewaytest.Env) {
			e.WriteNativeFile(legacyCaddyFile(e))
		}, "Caddy configuration"},
		{"wildcard data address", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			gatewaytest.Section(s, "data")["listen"] = "0.0.0.0:" + gatewaytest.Port(e.DataAddr)
			e.WriteNative(s)
		}, "data.listen"},
		{"timeout out of range", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			gatewaytest.Section(s, "upstream")["read_idle_timeout"] = "1h"
			e.WriteNative(s)
		}, "upstream.read_idle_timeout"},
		{"wildcard admin address", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			gatewaytest.Section(s, "gateway")["admin_listen"] = "0.0.0.0:" + gatewaytest.Port(e.Admin)
			e.WriteNative(s)
		}, "literal loopback address"},
		{"private key as the trust key", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			gatewaytest.Section(s, "gateway")["jwt"] = gatewaytest.TestTrust(issuertest.Name, issuertest.Audience, privateKey)
			e.WriteNative(s)
		}, "exactly one PEM PUBLIC KEY block"},
		{"missing trust key", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			gatewaytest.Section(s, "gateway")["jwt"] = gatewaytest.TestTrust(issuertest.Name, issuertest.Audience, filepath.Join(e.Dir, "absent.pem"))
			e.WriteNative(s)
		}, "jwt: opening public key"},
		{"dashboard directory without index.html", func(e *gatewaytest.Env) {
			s := e.NativeSettings()
			gatewaytest.Section(s, "gateway")["admin_ui"] = t.TempDir()
			e.WriteNative(s)
		}, "admin_ui"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
			tc.write(e)
			e.Run(gatewaytest.Binaries.Plain)
			if code := e.WaitExit(); code != gatewaytest.ExitFailed {
				t.Fatalf("exit status %d, want %d\n%s", code, gatewaytest.ExitFailed, e.Output)
			}
			if !strings.Contains(e.Output.String(), tc.cause) {
				t.Fatalf("refused for another reason, want %q:\n%s", tc.cause, e.Output)
			}
			if strings.Contains(e.Output.String(), "PRIVATE KEY") || strings.Contains(e.Output.String(), "MII") {
				t.Fatalf("the output discloses key material:\n%s", e.Output)
			}
			if gatewaytest.Dialable(e.DataAddr) || gatewaytest.Dialable(e.Admin) {
				t.Fatal("a listener is open")
			}
			if _, err := os.Stat(e.AuditLog); !os.IsNotExist(err) {
				t.Fatalf("an audit file was created: %v", err)
			}
			st, err := store.OpenStore(e.Database)
			if err != nil {
				t.Fatalf("the database is held: %v", err)
			}
			st.Close()
		})
	}

	// The command line names one command and its configuration file; no
	// Caddy command or saved-configuration resume exists, and version takes
	// no options.
	for _, args := range [][]string{
		{}, {"run"}, {"start", "--config", "x"}, {"run", "--config"}, {"run", "--resume"},
		{"run", "--config", "x", "--resume"}, {"run", "-r", "--config", "x"}, {"run", "--config", "x", "extra"}, {"run", "--config", "x", "--config", "y"},
		{"version", "--config", "x"}, {"list-modules"},
	} {
		e := gatewaytest.NewEnv(t)
		e.Launch(gatewaytest.Binaries.Plain, args)
		if code := e.WaitExit(); code != gatewaytest.ExitFailed || !strings.Contains(e.Output.String(), "usage: gateway run --config <file>") {
			t.Errorf("%v: exit %d\n%s", args, code, e.Output)
		}
	}
	e := gatewaytest.NewEnv(t)
	e.Launch(gatewaytest.Binaries.Plain, []string{"run", "--config", filepath.Join(e.Dir, "absent.json")})
	if code := e.WaitExit(); code != gatewaytest.ExitFailed || !strings.Contains(e.Output.String(), "configuration refused") {
		t.Errorf("missing configuration file: exit %d\n%s", code, e.Output)
	}
	if gatewaytest.Dialable(e.DataAddr) || gatewaytest.Dialable(e.Admin) {
		t.Error("a listener is open after a refused start")
	}
}
