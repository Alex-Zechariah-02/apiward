// The identity assertion for upstreams: a short-lived JWT, EdDSA (Ed25519)
// or ES256 by the key's type, the gateway
// signs for each request it forwards, naming the API, the verified account
// and its roles. An upstream holding the gateway's public key can check that
// a request passed this gateway instead of trusting the plain identity
// headers.

package pipeline

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
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
	// MaxAssertionBytes bounds a signed assertion: an upstream may refuse a
	// longer header (Fetch does), so a request whose assertion would exceed
	// it, through a long path or many roles, is refused instead.
	MaxAssertionBytes = 4096
	// coordinateBytes is the length of a P-256 coordinate and of each half
	// of an ES256 signature (RFC 7518, section 3.4).
	coordinateBytes = 32
)

// Signer signs assertions with one key: Ed25519, signing EdDSA (RFC 8037),
// or ECDSA P-256, signing ES256. The key's type fixes the algorithm (RFC
// 8725 section 3.1). It is immutable, so requests share it without a lock.
type Signer struct {
	ed ed25519.PrivateKey // set for an Ed25519 key
	ec *ecdsa.PrivateKey  // set for a P-256 key
	// prefix is the encoded JOSE header and the dot after it, the same for
	// every assertion of this key.
	prefix string
	jwks   []byte
	kid    string
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

// jwk is a public key as a JSON Web Key (RFC 7517): P-256 with x and y,
// Ed25519 with x only (RFC 8037 section 2).
type jwk struct {
	Type      string `json:"kty"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y,omitempty"`
	ID        string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
}

// LoadSigner reads the signing key at path: one PEM "PRIVATE KEY" block
// (PKCS #8) holding an Ed25519 or ECDSA P-256 key, in a file only its owner
// can read.
func LoadSigner(path string) (*Signer, error) {
	data, err := forward.ReadPEM(path, filecheck.Secret)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("the file must hold exactly one PEM PRIVATE KEY block (PKCS #8)")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the key is not valid PKCS #8")
	}
	switch key := parsed.(type) {
	case ed25519.PrivateKey:
		return newEdSigner(key)
	case *ecdsa.PrivateKey:
		if key.Curve == elliptic.P256() {
			return newSigner(key)
		}
	}
	return nil, errors.New("the key must be Ed25519 or ECDSA P-256")
}

// newEdSigner derives the key ID, the JOSE header and the published key set
// of an Ed25519 key. The key ID is the key's JWK thumbprint (RFC 7638
// section 3.2, RFC 8037 section 2: the required members in order).
func newEdSigner(key ed25519.PrivateKey) (*Signer, error) {
	x := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	thumbprint := sha256.Sum256(fmt.Appendf(nil, `{"crv":"Ed25519","kty":"OKP","x":"%s"}`, x))
	s, err := keySigner(base64.RawURLEncoding.EncodeToString(thumbprint[:]), "EdDSA", jwk{Type: "OKP", Curve: "Ed25519", X: x})
	if err != nil {
		return nil, err
	}
	s.ed = key
	return s, nil
}

// keySigner builds the header and key set shared by both key types.
func keySigner(kid, algorithm string, key jwk) (*Signer, error) {
	header, err := json.Marshal(map[string]string{"alg": algorithm, "kid": kid, "typ": "JWT"})
	if err != nil {
		return nil, err
	}
	key.ID, key.Use, key.Algorithm = kid, "sig", algorithm
	set, err := json.Marshal(map[string][]jwk{"keys": {key}})
	if err != nil {
		return nil, err
	}
	return &Signer{prefix: base64.RawURLEncoding.EncodeToString(header) + ".", jwks: set, kid: kid}, nil
}

// newSigner derives the key ID, the JOSE header and the published key set
// of a P-256 key. The key ID is the key's JWK thumbprint (RFC 7638).
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
	s, err := keySigner(base64.RawURLEncoding.EncodeToString(thumbprint[:]), "ES256", jwk{Type: "EC", Curve: "P-256", X: x, Y: y})
	if err != nil {
		return nil, err
	}
	s.ec = key
	return s, nil
}

// Checkpoint signs an audit checkpoint's message with the identity key and
// names the key; the audit chain's verifier checks it with the same public
// key set upstreams use.
func (s *Signer) Checkpoint(message []byte) (string, []byte, error) {
	signature, err := s.signature(message)
	return s.kid, signature, err
}

// KeyID returns the key ID, the key's JWK thumbprint.
func (s *Signer) KeyID() string { return s.kid }

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
	const signatureLength = 86 // 64 bytes, base64url without padding, for either key type
	token := make([]byte, 0, len(s.prefix)+base64.RawURLEncoding.EncodedLen(len(payload))+1+signatureLength)
	token = append(token, s.prefix...)
	token = base64.RawURLEncoding.AppendEncode(token, payload)
	signature, err := s.signature(token)
	if err != nil {
		return "", err
	}
	token = append(token, '.')
	return string(base64.RawURLEncoding.AppendEncode(token, signature)), nil
}

// signature signs the signing input: Ed25519 signs it itself (RFC 8037
// section 3.1); ES256 signs its SHA-256 and gives the two integers at fixed
// width, not the ASN.1 form (RFC 7518 section 3.4).
func (s *Signer) signature(input []byte) ([]byte, error) {
	if s.ed != nil {
		return ed25519.Sign(s.ed, input), nil
	}
	digest := sha256.Sum256(input)
	r, v, err := ecdsa.Sign(rand.Reader, s.ec, digest[:])
	if err != nil {
		return nil, err
	}
	signature := make([]byte, 2*coordinateBytes)
	r.FillBytes(signature[:coordinateBytes])
	v.FillBytes(signature[coordinateBytes:])
	return signature, nil
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
	if len(assertion) > MaxAssertionBytes {
		q.event.Reason = "assertion_too_large"
		q.reject(audit.StageBind, http.StatusBadRequest, "bad_request")
		return "", false
	}
	return assertion, true
}
