// The signed identity assertion an upstream receives.

package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// With an identity key the upstream receives one assertion per request, made
// by the gateway and not the client: it verifies with the key set the admin
// listener and the jwks command publish, and names the API, the verified
// account, its roles and the request ID, valid for 30 seconds.
func TestGatewaySignsIdentityAssertion(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(e.Dir, "identity.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := e.NativeSettings()
	gatewaytest.Section(settings, "upstream")["identity_key"] = keyFile
	e.WriteNative(settings)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)

	// The key set needs no session, and the command prints the same set.
	reply, err := http.Get("http://" + e.Admin + "/.well-known/apiward/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	published, _ := io.ReadAll(reply.Body)
	reply.Body.Close()
	printed, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "jwks")
	if reply.StatusCode != http.StatusOK || code != 0 || strings.TrimSpace(printed) != string(published) {
		t.Fatalf("key set: endpoint %d %s; command %d %s", reply.StatusCode, published, code, printed)
	}
	var set struct {
		Keys []struct{ Kty, Crv, X, Y, Kid, D string }
	}
	if err := json.Unmarshal(published, &set); err != nil || len(set.Keys) != 1 || set.Keys[0].D != "" {
		t.Fatalf("key set %s: %v", published, err)
	}
	decode := func(value string) []byte {
		data, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatalf("%q is not base64url: %v", value, err)
		}
		return data
	}
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// The uncompressed point is 0x04, X, Y.
	if !bytes.Equal(slices.Concat([]byte{4}, decode(set.Keys[0].X), decode(set.Keys[0].Y)), point) {
		t.Fatal("the published key is not the configured key's public half")
	}

	before := time.Now().Unix()
	header := append(gatewaytest.Bearer(t, "alice"), "X-Gateway-Assertion", "forged")
	if code, body := e.Get("/a/x", header...); code != http.StatusOK {
		t.Fatalf("admitted read: %d %s", code, body)
	}
	receipt := e.A.Receipts()[0]
	values := receipt.Headers.Values("X-Gateway-Assertion")
	if len(values) != 1 {
		t.Fatalf("upstream received assertions %q", values)
	}
	parts := strings.Split(values[0], ".")
	if len(parts) != 3 {
		t.Fatalf("assertion %q is not a compact JWS", values[0])
	}
	var protected struct{ Alg, Kid, Typ string }
	var claims struct {
		Iss, Aud, Sub, Jti string
		Roles              []string
		Iat, Exp           int64
	}
	if json.Unmarshal(decode(parts[0]), &protected) != nil || json.Unmarshal(decode(parts[1]), &claims) != nil {
		t.Fatalf("assertion %q does not decode", values[0])
	}
	signature := decode(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if protected.Alg != "ES256" || protected.Kid != set.Keys[0].Kid || len(signature) != 64 ||
		!ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatalf("assertion %q with header %+v does not verify with the configured key", values[0], protected)
	}
	if claims.Iss != "apiward" || claims.Aud != "a" || claims.Sub != "alice" || !slices.Equal(claims.Roles, []string{"WRITER"}) ||
		claims.Jti != receipt.RequestID || claims.Exp-claims.Iat != 30 || claims.Iat < before || claims.Iat > time.Now().Unix() {
		t.Fatalf("claims %+v for request %s", claims, receipt.RequestID)
	}
}
