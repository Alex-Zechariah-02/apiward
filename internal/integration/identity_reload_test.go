// Identity key hot-reload and retiring key JWKS tests.

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

func writeEdIdentityPair(t *testing.T, dir, prefix string) (privPath, pubPath, kid string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(dir, prefix+".pem")
	pubPath = filepath.Join(dir, prefix+".pub.pem")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := pipeline.LoadSigner(privPath)
	if err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath, signer.KeyID()
}

func jwtHeaderKid(t *testing.T, token string) string {
	t.Helper()
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	return h.Kid
}

func fetchJWKSKids(t *testing.T, e *gatewaytest.Env) []string {
	t.Helper()
	code, body, _ := e.AdminSend(http.MethodGet, pipeline.JWKSPath, "")
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", pipeline.JWKSPath, code, body)
	}
	set := fromJSON[struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}](t, body)
	kids := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

func TestReloadIdentityKey(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})

	priv1, pub1, kid1 := writeEdIdentityPair(t, e.Dir, "id1")
	priv2, _, kid2 := writeEdIdentityPair(t, e.Dir, "id2")

	settings := e.NativeSettings()
	gatewaytest.Section(settings, "gateway")["audit_max_bytes"] = 8192
	gatewaytest.Section(settings, "upstream")["identity_key"] = priv1
	e.WriteNative(settings)
	e.Start(gatewaytest.Binaries.Plain)

	admin := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	token := gatewaytest.Issuer.TokenFor(t, "alice")

	// Initial assertion uses kid1.
	e.ResetReceivers()
	if code, body := e.Get("/a/x", "Authorization", "Bearer "+token); code != http.StatusOK {
		t.Fatalf("initial GET /a/x: %d %s", code, body)
	}
	if got := jwtHeaderKid(t, e.A.Receipts()[0].Headers.Get(pipeline.AssertionHeader)); got != kid1 {
		t.Fatalf("initial assertion kid = %q, want %q", got, kid1)
	}

	// Switch to priv2 with pub1 retiring and reload.
	gatewaytest.Section(settings, "upstream")["identity_key"] = priv2
	gatewaytest.Section(settings, "upstream")["retiring_identity_key"] = pub1
	e.WriteNative(settings)
	code, body, _ := e.As(admin, http.MethodPost, "/admin/keys/reload", "", "Idempotency-Key", "reload-identity-key-01")
	if code != http.StatusOK {
		t.Fatalf("reload keys: %d %s", code, body)
	}

	// JWKS lists both kid2 and kid1.
	kids := fetchJWKSKids(t, e)
	if len(kids) != 2 || kids[0] != kid2 || kids[1] != kid1 {
		t.Fatalf("JWKS kids = %v, want [%s %s]", kids, kid2, kid1)
	}

	// Assertions after reload carry kid2.
	e.ResetReceivers()
	if code, body := e.Get("/a/x", "Authorization", "Bearer "+token); code != http.StatusOK {
		t.Fatalf("reloaded GET /a/x: %d %s", code, body)
	}
	if got := jwtHeaderKid(t, e.A.Receipts()[0].Headers.Get(pipeline.AssertionHeader)); got != kid2 {
		t.Fatalf("reloaded assertion kid = %q, want %q", got, kid2)
	}

	// Drive enough requests to rotate the 8 KiB audit log so a checkpoint is signed with kid2.
	for range 25 {
		if code, body := e.Get("/a/x", "Authorization", "Bearer "+token); code != http.StatusOK {
			t.Fatalf("traffic GET /a/x: %d %s", code, body)
		}
	}
	code, statusBody, _ := e.As(admin, http.MethodGet, "/admin/status", "")
	if code != http.StatusOK {
		t.Fatalf("GET /admin/status: %d %s", code, statusBody)
	}
	st := fromJSON[struct {
		AuditCheckpoint *struct {
			Kid string `json:"kid"`
		} `json:"audit_checkpoint"`
	}](t, statusBody)
	if st.AuditCheckpoint == nil || st.AuditCheckpoint.Kid != kid2 {
		t.Fatalf("checkpoint after reload = %+v, want kid %q", st.AuditCheckpoint, kid2)
	}

	// Setting retiring_identity_key to a private key file is refused on reload.
	gatewaytest.Section(settings, "upstream")["retiring_identity_key"] = priv1
	e.WriteNative(settings)
	code, _, _ = e.As(admin, http.MethodPost, "/admin/keys/reload", "", "Idempotency-Key", "reload-identity-key-bad")
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("reload with private key as retiring_identity_key: %d, want 422", code)
	}

	// Removing retiring_identity_key and reloading leaves only kid2 in JWKS.
	delete(gatewaytest.Section(settings, "upstream"), "retiring_identity_key")
	e.WriteNative(settings)
	code, body, _ = e.As(admin, http.MethodPost, "/admin/keys/reload", "", "Idempotency-Key", "reload-identity-key-02")
	if code != http.StatusOK {
		t.Fatalf("second reload: %d %s", code, body)
	}
	kids = fetchJWKSKids(t, e)
	if len(kids) != 1 || kids[0] != kid2 {
		t.Fatalf("JWKS kids after removing retiring key = %v, want [%s]", kids, kid2)
	}
}
