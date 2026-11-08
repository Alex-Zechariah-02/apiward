// The test issuer: an RS256 key held in memory, the claims tests use and the
// tokens, well-formed or deliberately broken, signed with it.

package issuertest

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The test process acts as the external token issuer. Its signing keys are
// generated in memory for each run and never written anywhere: the gateway
// receives only the public key, through a file in the test environment.
const (
	Name     = "https://issuer.test"
	Audience = "gateway.test"
)

type Issuer struct {
	key *rsa.PrivateKey
}

// Key is the signing key, for tests that write it in a form the
// gateway must refuse.
func (i *Issuer) Key() *rsa.PrivateKey { return i.key }

func New(bits int) *Issuer {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return &Issuer{key: key}
}

// PublicPEM is the verification key in the form the gateway accepts.
func (i *Issuer) PublicPEM() []byte {
	der, err := x509.MarshalPKIXPublicKey(&i.key.PublicKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Changed returns a copy of base with changes applied; a nil value removes
// that member.
func Changed(base, changes map[string]any) map[string]any {
	result := maps.Clone(base)
	for name, value := range changes {
		if value == nil {
			delete(result, name)
			continue
		}
		result[name] = value
	}
	return result
}

// ValidClaims is a claim set the gateway accepts for subject, valid for ten
// minutes from now.
func ValidClaims(subject string) map[string]any {
	now := time.Now()
	return map[string]any{
		"sub":   subject,
		"iss":   Name,
		"aud":   Audience,
		"iat":   now.Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
		"roles": Roles(subject),
	}
}

// The isolated test issuer's account catalogue is independent of gateway
// policies. Tests changing assertions sign an explicit roles claim instead.
func Roles(subject string) []string {
	switch subject {
	case "alice":
		return []string{"WRITER"}
	case "bob", "dave":
		return []string{"READER"}
	case "carol":
		return []string{"TRIAL"}
	case "cust-001", "cust-002":
		return []string{"CUSTOMER"}
	case "staff-01", "former-01":
		return []string{"STAFF"}
	case "mgr-01":
		return []string{"MANAGER"}
	case "lead-01":
		return []string{"MANAGER", "STAFF"}
	case "both@example.test":
		return []string{"CUSTOMER", "STAFF"}
	}
	return []string{}
}

// Subject is solely a legacy-input test fixture. It is not a policy type.
type Subject struct {
	ID     string   `json:"id"`
	Status string   `json:"status"`
	Roles  []string `json:"roles"`
}

// Token signs claims with go-jose's own signer, as an ordinary issuer would.
func (i *Issuer) Token(t testing.TB, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: i.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-a"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// TokenFor is a valid token for subject.
func (i *Issuer) TokenFor(t testing.TB, subject string) string {
	t.Helper()
	return i.Token(t, ValidClaims(subject))
}

// SignRaw signs a hand-written header and payload with RS256, so tests can
// produce tokens that no well-behaved signer would: repeated members, wrong
// claim types, unusual headers.
func (i *Issuer) SignRaw(header, payload string) string {
	input := EncodeSegment(header) + "." + EncodeSegment(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// HMACToken signs with HS256, using secret as the HMAC key. With the
// gateway's public key bytes as the secret this is the classic RSA/HMAC
// confusion attack.
func HMACToken(secret []byte, payload string) string {
	input := EncodeSegment(`{"alg":"HS256","typ":"JWT"}`) + "." + EncodeSegment(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func EncodeSegment(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func ClaimsJSON(claims map[string]any) string {
	data, _ := json.Marshal(claims)
	return string(data)
}
