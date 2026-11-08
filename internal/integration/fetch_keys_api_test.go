// Fetch trust key reloads through the Admin API: permissions, key material
// and concurrent reloads.

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
)

func TestFetchKeyReload(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	s := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	code, body, _ := e.As(s, http.MethodGet, "/admin/keys", "")
	if code != http.StatusOK {
		t.Fatalf("keys list: %d %s", code, body)
	}
	var before struct {
		Items []pipeline.KeyInfo `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &before); err != nil || len(before.Items) != 1 || before.Items[0].Kid != "test-a" || !strings.HasPrefix(before.Items[0].Fingerprint, "sha256:") || before.Items[0].LoadedAt.IsZero() {
		t.Fatalf("key metadata: %s (%v)", body, err)
	}
	other := issuertest.New(2048)
	keyFile := filepath.Join(e.Dir, "next.pem")
	if err := os.WriteFile(keyFile, other.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	config := e.NativeSettings()
	trust := gatewaytest.TestTrust(issuertest.Name, issuertest.Audience, e.PublicKey)
	trust.Keys = append(trust.Keys, pipeline.VerificationKey{Kid: "test-b", PublicKeyFile: keyFile})
	gatewaytest.Section(config, "gateway")["jwt"] = trust
	e.WriteNative(config)
	post := func(key string) (int, string) {
		code, body, _ := e.As(s, http.MethodPost, "/admin/keys/reload", "", "Idempotency-Key", key)
		return code, body
	}
	// A token verified before the reload is still counted after it.
	if code, body := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice")); code != http.StatusOK {
		t.Fatalf("before reload: %d %s", code, body)
	}
	code, reloaded := post("keys-reload-accept-01")
	if code != http.StatusOK {
		t.Fatalf("valid reload: %d %s", code, reloaded)
	}
	oldToken := gatewaytest.Issuer.TokenFor(t, "alice")
	newToken := other.SignRaw(`{"alg":"RS256","typ":"JWT","kid":"test-b"}`, issuertest.ClaimsJSON(issuertest.ValidClaims("alice")))
	for _, token := range []string{oldToken, newToken} {
		if code, body := e.Get("/a/x", "Authorization", "Bearer "+token); code != http.StatusOK {
			t.Fatalf("rotated keys: %d %s", code, body)
		}
	}
	// A bad on-disk key cannot replace the validated whole set. Replaying the
	// accepted mutation must return its original list without re-reading disk.
	if err := os.WriteFile(keyFile, []byte("invalid key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, replayed := post("keys-reload-accept-01"); code != 200 || replayed != reloaded {
		t.Fatalf("reload replay changed its result: %d %s", code, replayed)
	}
	if code, body := post("keys-reload-invalid-01"); code != http.StatusUnprocessableEntity || !strings.Contains(body, `"keys_invalid"`) {
		t.Fatalf("invalid reload: %d %s", code, body)
	}
	if code, body := e.Get("/a/x", "Authorization", "Bearer "+newToken); code != 200 {
		t.Fatalf("failed reload lost the old set: %d %s", code, body)
	}
	// Each key counts the tokens it verified since the gateway started; a
	// token refused at the signature check counts for no key.
	if code, _ := e.Get("/a/x", "Authorization", "Bearer "+oldToken[:len(oldToken)-4]+"AAAA"); code != http.StatusUnauthorized {
		t.Fatalf("tampered token: %d", code)
	}
	code, body, _ = e.As(s, http.MethodGet, "/admin/keys", "")
	var used struct {
		Items []struct {
			Kid            string     `json:"kid"`
			Verified       uint64     `json:"verified"`
			LastVerifiedAt *time.Time `json:"last_verified_at"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &used); code != 200 || err != nil || len(used.Items) != 2 {
		t.Fatalf("key use: %d %s (%v)", code, body, err)
	}
	for _, item := range used.Items {
		want := map[string]uint64{"test-a": 2, "test-b": 2}[item.Kid]
		if item.Verified != want || item.LastVerifiedAt == nil || time.Since(*item.LastVerifiedAt) > time.Minute {
			t.Errorf("key %s: verified %d (want %d), last %v", item.Kid, item.Verified, want, item.LastVerifiedAt)
		}
	}
	// Retiring a key is independent of policy rollback.
	trust.Keys = []pipeline.VerificationKey{{Kid: "test-b", PublicKeyFile: keyFile}}
	if err := os.WriteFile(keyFile, other.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	gatewaytest.Section(config, "gateway")["jwt"] = trust
	e.WriteNative(config)
	if code, body := post("keys-retire-old-01"); code != 200 {
		t.Fatalf("retirement: %d %s", code, body)
	}
	_, provisional := e.ProvisionalFrom(s, e.ProtectedPolicy(), 1, 60, "keys-policy-trial")
	if code, _, body := e.Resolve(s, "rollback", provisional.Provisional, `"r1"`, "keys-policy-rollback"); code != 200 {
		t.Fatalf("rollback: %d %s", code, body)
	}
	if code, _ := e.Get("/a/x", "Authorization", "Bearer "+oldToken); code != 401 {
		t.Fatalf("rollback re-trusted retired key: %d", code)
	}
	if code, _ := e.Get("/a/x", "Authorization", "Bearer "+newToken); code != 200 {
		t.Fatalf("rollback lost current key: %d", code)
	}
}

func TestFetchKeyReloadPermissionsAndHTTPMaterial(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	_, password := addAdmin(e, gatewaytest.Binaries.Plain, "reader", "read")
	e.Start(gatewaytest.Binaries.Plain)
	reader := e.MustLogin("reader", password)
	if code, _, _ := e.AdminSend(http.MethodGet, "/admin/keys", ""); code != 401 {
		t.Fatalf("unauthenticated key list: %d", code)
	}
	if code, body, _ := e.As(reader, http.MethodGet, "/admin/keys", ""); code != 200 {
		t.Fatalf("reader cannot list: %d %s", code, body)
	}
	if code, _, _ := e.As(reader, http.MethodPost, "/admin/keys/reload", "", "Idempotency-Key", "keys-reader-forbidden"); code != 403 {
		t.Fatalf("reader reloaded keys: %d", code)
	}
	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	if code, _, _ := e.As(admin, http.MethodPost, "/admin/keys/reload", `{"keys":[]}`, "Idempotency-Key", "keys-http-material-01"); code != 400 {
		t.Fatalf("reload accepted HTTP material: %d", code)
	}
	if code, _, _ := e.As(admin, http.MethodPost, "/admin/keys/reload", ""); code != 400 {
		t.Fatalf("reload accepted no idempotency key: %d", code)
	}
}

// Repeated whole-set reloads while requests verify must not publish a
// partial set or race. Both keys remain configured through this test.
func TestFetchConcurrentKeyReload(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	other := issuertest.New(2048)
	keyFile := filepath.Join(e.Dir, "concurrent.pem")
	if err := os.WriteFile(keyFile, other.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	config := e.NativeSettings()
	trust := gatewaytest.TestTrust(issuertest.Name, issuertest.Audience, e.PublicKey)
	trust.Keys = append(trust.Keys, pipeline.VerificationKey{Kid: "test-b", PublicKeyFile: keyFile})
	gatewaytest.Section(config, "gateway")["jwt"] = trust
	e.WriteNative(config)
	e.Start(gatewaytest.Binaries.Plain)
	s := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	tokens := []string{gatewaytest.Issuer.TokenFor(t, "alice"), other.SignRaw(`{"alg":"RS256","typ":"JWT","kid":"test-b"}`, issuertest.ClaimsJSON(issuertest.ValidClaims("alice")))}
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for range 10 {
				if code, _ := e.Get("/a/x", "Authorization", "Bearer "+tokens[worker%2]); code != 200 {
					t.Errorf("worker %d saw partial trust: %d", worker, code)
				}
			}
		})
	}
	for range 5 {
		code, body, _ := e.As(s, http.MethodPost, "/admin/keys/reload", "", "Idempotency-Key", "keys-concurrent-"+session.NewToken()[:16])
		if code != 200 {
			t.Errorf("reload: %d %s", code, body)
		}
	}
	wg.Wait()
}
