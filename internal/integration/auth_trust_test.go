// Trust material at startup.

package integration

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// The gateway does not start without valid trust material, and changing a
// key file alone changes nothing: keys are replaced by a reload or restart.
func TestTrustMaterialAtStartup(t *testing.T) {
	other := issuertest.New(2048)
	privateKey := filepath.Join(t.TempDir(), "private.pem")
	der, _ := x509.MarshalPKCS8PrivateKey(other.Key())
	os.WriteFile(privateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)

	trust := func(e *gatewaytest.Env, changes map[string]any) map[string]any {
		config := map[string]any{"issuer": issuertest.Name, "audience": issuertest.Audience, "keys": []pipeline.VerificationKey{{Kid: "test-a", PublicKeyFile: e.PublicKey}}}
		return issuertest.Changed(config, changes)
	}
	// cause is the part of the startup error that shows why it was refused.
	// The gateway logs the error as JSON, so quotes inside it appear escaped.
	cases := []struct {
		name    string
		changes func(e *gatewaytest.Env) any
		cause   string
	}{
		{"no trust configuration", func(e *gatewaytest.Env) any { return map[string]any{} }, "gateway.jwt.issuer is required"},
		{"missing key file", func(e *gatewaytest.Env) any {
			return trust(e, map[string]any{"keys": []pipeline.VerificationKey{{Kid: "test-a", PublicKeyFile: filepath.Join(e.Dir, "absent.pem")}}})
		}, "jwt: opening public key"},
		{"private key given as the key", func(e *gatewaytest.Env) any {
			return trust(e, map[string]any{"keys": []pipeline.VerificationKey{{Kid: "test-a", PublicKeyFile: privateKey}}})
		}, "exactly one PEM PUBLIC KEY block"},
		{"no issuer", func(e *gatewaytest.Env) any { return trust(e, map[string]any{"issuer": nil}) }, "gateway.jwt.issuer is required"},
		{"no audience", func(e *gatewaytest.Env) any { return trust(e, map[string]any{"audience": nil}) }, "gateway.jwt.audience is required"},
		{"several audiences", func(e *gatewaytest.Env) any {
			return trust(e, map[string]any{"audience": []string{issuertest.Audience, "other"}})
		}, "gateway.jwt.audience: a JSON array is not a valid value"},
		{"remote key set", func(e *gatewaytest.Env) any { return trust(e, map[string]any{"jwks_url": "http://127.0.0.1:1/jwks"}) }, `unknown field \"jwks_url\"`},
		{"second issuer", func(e *gatewaytest.Env) any {
			return trust(e, map[string]any{"issuers": []string{"https://other.test"}})
		}, `unknown field \"issuers\"`},
		{"clock leeway", func(e *gatewaytest.Env) any { return trust(e, map[string]any{"leeway": "30s"}) }, `unknown field \"leeway\"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := gatewaytest.NewEnv(t)
			gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
			e.WriteConfig(gatewaytest.ConfigOptions{JWT: tc.changes(e)})
			e.Launch(gatewaytest.Binaries.Plain, []string{"run", "--config", e.Config})
			if code := e.WaitExit(); code == 0 {
				t.Fatalf("gateway ran without valid trust material\n%s", e.Output)
			}
			if !strings.Contains(e.Output.String(), tc.cause) {
				t.Fatalf("refused for another reason, want %q:\n%s", tc.cause, e.Output)
			}
			if gatewaytest.Dialable(e.DataAddr) || gatewaytest.Dialable(e.Admin) {
				t.Fatal("a listener is open after the refused start")
			}
			if strings.Contains(e.Output.String(), "PRIVATE KEY") || strings.Contains(e.Output.String(), "MII") {
				t.Fatalf("startup output discloses key material:\n%s", e.Output)
			}
		})
	}

	t.Run("key replaced by restart", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		oldToken, newToken := gatewaytest.Issuer.TokenFor(t, "alice"), other.TokenFor(t, "alice")
		before := e.Status().JWTKey
		if code, _ := e.Get("/a/x", "Authorization", "Bearer "+oldToken); code != http.StatusOK {
			t.Fatalf("token from the configured key: %d", code)
		}
		if code, _ := e.Get("/a/x", "Authorization", "Bearer "+newToken); code != http.StatusUnauthorized {
			t.Fatalf("token from the replacement key before restart: %d", code)
		}

		// Replacing the file changes nothing until the gateway restarts.
		if err := os.WriteFile(e.PublicKey, other.PublicPEM(), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _ := e.Get("/a/x", "Authorization", "Bearer "+newToken); code != http.StatusUnauthorized || e.Status().JWTKey != before {
			t.Fatalf("replacement key used without a restart: %d", code)
		}

		e.Start(gatewaytest.Binaries.Plain)
		if e.Status().JWTKey == before || len(e.Status().JWTKey) != 64 {
			t.Fatalf("fingerprint %q after restart, was %q", e.Status().JWTKey, before)
		}
		if code, _ := e.Get("/a/x", "Authorization", "Bearer "+oldToken); code != http.StatusUnauthorized {
			t.Fatalf("token from the old key after restart: %d", code)
		}
		if code, _ := e.Get("/a/x", "Authorization", "Bearer "+newToken); code != http.StatusOK {
			t.Fatalf("token from the new key after restart: %d", code)
		}
		e.AssertReceipts(2, 0, 0)
	})
}
