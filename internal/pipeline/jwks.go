// Retiring identity public key parsing and JWK Set construction.

package pipeline

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
)

// WithRetiringKey returns a copy of s that also publishes the public key at
// path in its JWK Set, without signing with it. Path must hold one PEM PUBLIC
// KEY block (Ed25519 or ECDSA P-256) distinct from s's own key.
func (s *Signer) WithRetiringKey(path string) (*Signer, error) {
	if path == "" {
		return s, nil
	}
	data, err := forward.ReadPEM(path, filecheck.Trusted)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("the file must hold exactly one PEM PUBLIC KEY block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the key is not a valid public key")
	}
	ret, err := publicJWK(parsed)
	if err != nil {
		return nil, err
	}
	if ret.ID == s.kid {
		return nil, errors.New("retiring identity key matches the active identity key")
	}
	set, err := json.Marshal(map[string][]jwk{"keys": {s.key, ret}})
	if err != nil {
		return nil, err
	}
	out := *s
	out.jwks = set
	return &out, nil
}

// publicJWK is the published JWK of an Ed25519 or P-256 public key. Its ID is
// the key's JWK thumbprint: RFC 7638 section 3.2 (RFC 8037 section 2 for
// Ed25519), the required members in lexicographic order.
func publicJWK(pub any) (jwk, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		x := base64.RawURLEncoding.EncodeToString(k)
		sum := sha256.Sum256(fmt.Appendf(nil, `{"crv":"Ed25519","kty":"OKP","x":"%s"}`, x))
		kid := base64.RawURLEncoding.EncodeToString(sum[:])
		return jwk{Type: "OKP", Curve: "Ed25519", X: x, ID: kid, Use: "sig", Algorithm: "EdDSA"}, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return jwk{}, errors.New("the key must be Ed25519 or ECDSA P-256")
		}
		encoded, err := k.Bytes()
		if err != nil {
			return jwk{}, err
		}
		// The uncompressed point is 0x04, X, Y.
		point := encoded[1:]
		x := base64.RawURLEncoding.EncodeToString(point[:coordinateBytes])
		y := base64.RawURLEncoding.EncodeToString(point[coordinateBytes:])
		sum := sha256.Sum256(fmt.Appendf(nil, `{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y))
		kid := base64.RawURLEncoding.EncodeToString(sum[:])
		return jwk{Type: "EC", Curve: "P-256", X: x, Y: y, ID: kid, Use: "sig", Algorithm: "ES256"}, nil
	default:
		return jwk{}, errors.New("the key must be Ed25519 or ECDSA P-256")
	}
}
