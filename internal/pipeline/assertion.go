// The identity assertion for upstreams: a short-lived ES256 JWT the gateway
// signs for each request it forwards, naming the API, the verified account
// and its roles. An upstream holding the gateway's public key can check that
// a request passed this gateway instead of trusting the plain identity
// headers.

package pipeline

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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
)

const (
	// AssertionHeader carries the assertion; like every X-Gateway- header a
	// client's copy is removed at ingress.
	AssertionHeader = "X-Gateway-Assertion"
	// JWKSPath is where the admin listener publishes the public key.
	JWKSPath = "/.well-known/apiward/jwks.json"
	// AssertionIssuer is the "iss" of every assertion; the key ID tells
	// gateways apart.
	AssertionIssuer = "apiward"
	// AssertionLife bounds how long a captured assertion could be replayed.
	AssertionLife = 30 * time.Second
	// coordinateBytes is the length of a P-256 coordinate and of each half
	// of an ES256 signature (RFC 7518, section 3.4).
	coordinateBytes = 32
)

// Signer signs assertions with one ECDSA P-256 key. It is immutable, so
// requests share it without a lock.
type Signer struct {
	key *ecdsa.PrivateKey
	// prefix is the encoded JOSE header and the dot after it, the same for
	// every assertion of this key.
	prefix string
	jwks   []byte
}

// claims is the assertion's payload. A public operation has no account, so
// "sub" and "roles" are then absent. Method and Path name the one request
// the assertion was made for, as the upstream receives it: the path is the
// forwarded one, decoded and without the query.
type claims struct {
	Issuer   string   `json:"iss"`
	Audience string   `json:"aud"`
	Subject  string   `json:"sub,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Method   string   `json:"method"`
	Path     string   `json:"path"`
	IssuedAt int64    `json:"iat"`
	Expires  int64    `json:"exp"`
	ID       string   `json:"jti"`
}

// jwk is a public P-256 key as a JSON Web Key (RFC 7517).
type jwk struct {
	Type      string `json:"kty"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
	ID        string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
}

// LoadSigner reads the signing key at path: one PEM "PRIVATE KEY" block
// (PKCS #8) holding an ECDSA P-256 key, in a file only its owner can read.
func LoadSigner(path string) (*Signer, error) {
	if err := forward.CheckKeyFile(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if len(data) > maxKeyFileBytes || block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("the file must hold exactly one PEM PRIVATE KEY block (PKCS #8)")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the key is not valid PKCS #8")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("the key must be ECDSA P-256")
	}
	return newSigner(key)
}

// newSigner derives the key ID, the JOSE header and the published key set
// from key. The key ID is the key's JWK thumbprint (RFC 7638).
func newSigner(key *ecdsa.PrivateKey) (*Signer, error) {
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	// The uncompressed point is 0x04, X, Y.
	point := encoded[1:]
	x := base64.RawURLEncoding.EncodeToString(point[:coordinateBytes])
	y := base64.RawURLEncoding.EncodeToString(point[coordinateBytes:])
	// RFC 7638, section 3.2: the required members in lexicographic order.
	thumbprint := sha256.Sum256(fmt.Appendf(nil, `{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y))
	kid := base64.RawURLEncoding.EncodeToString(thumbprint[:])
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": kid, "typ": "JWT"})
	if err != nil {
		return nil, err
	}
	set, err := json.Marshal(map[string][]jwk{"keys": {{Type: "EC", Curve: "P-256", X: x, Y: y, ID: kid, Use: "sig", Algorithm: "ES256"}}})
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, prefix: base64.RawURLEncoding.EncodeToString(header) + ".", jwks: set}, nil
}

// JWKS returns the public key as a JSON Web Key Set; nil without a signer.
func (s *Signer) JWKS() []byte {
	if s == nil {
		return nil
	}
	return s.jwks
}

// sign returns the compact assertion for one forwarded request, described by
// c; it sets the issuer and the times, expiring AssertionLife after now.
func (s *Signer) sign(c claims, now time.Time) (string, error) {
	c.Issuer, c.IssuedAt, c.Expires = AssertionIssuer, now.Unix(), now.Add(AssertionLife).Unix()
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	const signatureLength = 86 // two coordinates, base64url without padding
	token := make([]byte, 0, len(s.prefix)+base64.RawURLEncoding.EncodedLen(len(payload))+1+signatureLength)
	token = append(token, s.prefix...)
	token = base64.RawURLEncoding.AppendEncode(token, payload)
	digest := sha256.Sum256(token)
	r, v, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	// JOSE wants the two integers at fixed width, not the ASN.1 form.
	var signature [2 * coordinateBytes]byte
	r.FillBytes(signature[:coordinateBytes])
	v.FillBytes(signature[coordinateBytes:])
	token = append(token, '.')
	return string(base64.RawURLEncoding.AppendEncode(token, signature[:])), nil
}

// assert signs the assertion of a request that passed every check, before
// its admission is recorded. Without a signer there is none. A request whose
// assertion cannot be signed is refused: forwarding it bare would let an
// upstream that requires the assertion see the gateway as an impostor. method
// and path are the request's as forwarded, so the upstream can refuse the
// assertion on any other request.
func (h *Handler) assert(q *request, rule *compile.Rule, roles []string, method, path string) (assertion string, ok bool) {
	if h.signer == nil {
		return "", true
	}
	c := claims{Audience: rule.API(), ID: q.event.RequestID, Method: method, Path: path}
	if !rule.Public() {
		c.Subject, c.Roles = q.event.Subject, roles
	}
	assertion, err := h.signer.sign(c, time.Now())
	if err != nil {
		q.reject(audit.StageBind, http.StatusServiceUnavailable, "gateway_unavailable")
		return "", false
	}
	return assertion, true
}
