// Test tokens: one RSA key pair per run, and a token for each identity a probe names.

package migrate

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/probe"
	"github.com/Alex-Zechariah-02/apiward/internal/semantics"
)

// signerKey is the key ID the gateway's trust configuration names.
const signerKey = "probe"

// signer issues the probes' tokens; its private key lives only in this process.
type signer struct {
	key              *rsa.PrivateKey
	issuer, audience string
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: key, issuer: "https://login.probe.example", audience: "probe-gateway"}
}

// publicPEM is the verification key, as the gateway and Kong read it.
func (s *signer) publicPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// token returns the Authorization value of a probe identity; none sends nothing.
func (s *signer) token(identity string) string {
	now := time.Now()
	claims := map[string]any{"iss": s.issuer, "aud": s.audience, "sub": "probe-caller", "iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(), "roles": []string{}}
	switch identity {
	case string(semantics.NoToken):
		return ""
	case string(semantics.Malformed):
		return "Bearer not.a.token"
	case string(semantics.Expired):
		claims["iat"], claims["exp"] = now.Add(-time.Hour).Unix(), now.Add(-30*time.Minute).Unix()
	case string(semantics.WrongIssuer):
		claims["iss"] = "https://other.probe.example"
	case string(semantics.WrongAudience):
		claims["aud"] = "other-gateway"
	}
	if role := probe.Role(identity); role != "" {
		claims["roles"] = []string{role}
	}
	return "Bearer " + s.sign(claims)
}

func (s *signer) sign(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": signerKey})
	payload, _ := json.Marshal(claims)
	encode := base64.RawURLEncoding.EncodeToString
	signed := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return signed + "." + encode(signature)
}
