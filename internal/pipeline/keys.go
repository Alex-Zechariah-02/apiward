// Trusted issuer configuration and verification key loading.

package pipeline

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

const (
	// MaxTokenBytes bounds a bearer token before it is decoded: 4 KiB is
	// the cookie size RFC 6265 requires browsers to hold, which issuers keep
	// tokens within; a Fetch token is under 1 KiB.
	MaxTokenBytes = 4096
	// maxTrustValue bounds the issuer and audience: both are short names or
	// URLs, and RFC 7519 sets no bound of its own.
	maxTrustValue = 256
	// maxRSABits is the largest key common tools generate; verification
	// cost grows with the key, so larger keys would slow every request.
	maxRSABits = 8192
	// MaxKeys bounds the key set: a rotation keeps two or three keys, and
	// every key is read again on each reload.
	MaxKeys = 64
	// DefaultClockSkew is the leeway on "exp" and "nbf" when none is set,
	// Envoy's default; MaxClockSkew bounds the setting.
	DefaultClockSkew = 60 * time.Second
	MaxClockSkew     = 300 * time.Second
	// maxNumericDate is 9999-12-31T23:59:59Z, so every accepted time claim
	// converts to a time.Time without overflow.
	maxNumericDate = 253402300799
)

// TrustConfig names the trusted issuer, audience and locally configured public
// keys. Token headers can select only a key already in this set.
type TrustConfig struct {
	Issuer   string            `json:"issuer"`
	Audience string            `json:"audience"`
	Keys     []VerificationKey `json:"keys"`
	// ClockSkew is the leeway on "exp" and "nbf" (a duration, "0s" for
	// exact times); omitted, DefaultClockSkew.
	ClockSkew *string `json:"clock_skew,omitempty"`
	// MinRSABits is the smallest key accepted: 2048 (omitted), 3072 or 4096.
	MinRSABits *int `json:"min_rsa_bits,omitempty"`
}

type VerificationKey struct {
	Kid           string `json:"kid"`
	PublicKeyFile string `json:"public_key_file"`
}

type KeyInfo struct {
	Kid         string    `json:"kid"`
	Fingerprint string    `json:"fingerprint"`
	Bits        int       `json:"bits"`
	LoadedAt    time.Time `json:"loaded_at"`
}

// A verifier is an immutable whole key set. Replacing one never mutates keys
// that a request has already captured.
type Verifier struct {
	issuer      string
	audience    string
	keys        map[string]*rsa.PublicKey
	info        []KeyInfo
	fingerprint string // SHA-256 of the complete named key set
	// skew is the leeway on the token's validity times.
	skew time.Duration
	// uses counts verified tokens per key since the gateway started. The map
	// is fixed when the verifier is built; a reload carries a kept key's
	// counter over (adoptUses), so only the counters' atomics change.
	uses map[string]*KeyUse
}

// KeyUse counts the tokens one key verified and when it last did. It is read
// by the keys report and written by verify with atomics only, so counting
// adds no lock to a request.
type KeyUse struct {
	verified atomic.Uint64
	lastNano atomic.Int64
}

// AdoptUses gives v the counters of the keys it shares with previous, before
// v is published, so a reload keeps their counts. A key is shared when both
// its ID and its material match: an ID reused for a new key starts at zero.
func (v *Verifier) AdoptUses(previous *Verifier) {
	kept := map[KeyInfo]bool{}
	for _, info := range previous.info {
		kept[KeyInfo{Kid: info.Kid, Fingerprint: info.Fingerprint}] = true
	}
	for _, info := range v.info {
		if kept[KeyInfo{Kid: info.Kid, Fingerprint: info.Fingerprint}] {
			v.uses[info.Kid] = previous.uses[info.Kid]
		}
	}
}

// LoadVerifier reads and validates the trust configuration. The key file must
// hold exactly one PEM "PUBLIC KEY" block with an RSA key, so a private key or
// any other material is refused.
func LoadVerifier(c TrustConfig) (*Verifier, error) {
	if !isTrustValue(c.Issuer) || !isTrustValue(c.Audience) {
		return nil, fmt.Errorf("issuer and audience must each be 1 to %d printable ASCII characters", maxTrustValue)
	}
	if len(c.Keys) == 0 || len(c.Keys) > MaxKeys {
		return nil, fmt.Errorf("keys must contain 1 to %d named public keys", MaxKeys)
	}
	skew, minBits, err := c.bounds()
	if err != nil {
		return nil, err
	}
	v := &Verifier{issuer: c.Issuer, audience: c.Audience, skew: skew, keys: map[string]*rsa.PublicKey{}, info: []KeyInfo{}, uses: map[string]*KeyUse{}}
	loaded := time.Now().UTC()
	for _, entry := range c.Keys {
		if policy.CheckID(entry.Kid, "kid") != nil || v.keys[entry.Kid] != nil {
			return nil, errors.New("key IDs must be valid and distinct")
		}
		key, fingerprint, err := readVerificationKey(entry.PublicKeyFile, minBits)
		if err != nil {
			return nil, err
		}
		v.keys[entry.Kid] = key
		v.uses[entry.Kid] = &KeyUse{}
		v.info = append(v.info, KeyInfo{Kid: entry.Kid, Fingerprint: "sha256:" + fingerprint, Bits: key.N.BitLen(), LoadedAt: loaded})
	}
	slices.SortFunc(v.info, func(a, b KeyInfo) int { return strings.Compare(a.Kid, b.Kid) })
	hash := sha256.New()
	for _, info := range v.info {
		fmt.Fprintf(hash, "%s:%s\n", info.Kid, info.Fingerprint)
	}
	v.fingerprint = hex.EncodeToString(hash.Sum(nil))
	return v, nil
}

// bounds resolves the clock skew and the smallest RSA key size.
func (c TrustConfig) bounds() (time.Duration, int, error) {
	skew, minBits := DefaultClockSkew, 2048
	if c.ClockSkew != nil {
		parsed, err := time.ParseDuration(*c.ClockSkew)
		if err != nil || parsed < 0 || parsed > MaxClockSkew {
			return 0, 0, fmt.Errorf("clock_skew must be a duration from 0s to %s", MaxClockSkew)
		}
		skew = parsed
	}
	if c.MinRSABits != nil {
		if !slices.Contains([]int{2048, 3072, 4096}, *c.MinRSABits) {
			return 0, 0, errors.New("min_rsa_bits must be 2048, 3072 or 4096")
		}
		minBits = *c.MinRSABits
	}
	return skew, minBits, nil
}

func readVerificationKey(path string, minBits int) (*rsa.PublicKey, string, error) {
	data, err := forward.ReadPEM(path, nil)
	if err != nil {
		return nil, "", fmt.Errorf("reading public key: %w", err)
	}

	// pem.Decode skips text before the first block, so leading data is
	// checked separately.
	block, rest := pem.Decode(data)
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) ||
		block == nil ||
		block.Type != "PUBLIC KEY" ||
		len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", errors.New("public key file must hold exactly one PEM PUBLIC KEY block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parsing public key: %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, "", errors.New("public key is not an RSA key")
	}
	if bits := key.N.BitLen(); bits < minBits || bits > maxRSABits {
		return nil, "", fmt.Errorf("RSA key has %d bits, want %d to %d", bits, minBits, maxRSABits)
	}

	sum := sha256.Sum256(block.Bytes)
	return key, hex.EncodeToString(sum[:]), nil
}

func isTrustValue(value string) bool {
	if value == "" || len(value) > maxTrustValue {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// keyList returns the loaded keys, in configuration order.
func (v *Verifier) Keys() []KeyInfo { return v.info }

// keySet is the SHA-256 of the complete named key set.
func (v *Verifier) Fingerprint() string { return v.fingerprint }

// trustedIssuer is the only issuer whose tokens verify.
func (v *Verifier) Issuer() string { return v.issuer }

// trustedAudience is the audience a token must name.
func (v *Verifier) Audience() string { return v.audience }

// use returns the counters of one key, or nil for a key not loaded.
func (v *Verifier) Use(kid string) *KeyUse { return v.uses[kid] }

// count returns the tokens the key verified since the gateway started.
func (u *KeyUse) Count() uint64 { return u.verified.Load() }

// last returns when the key last verified a token, in Unix nanoseconds; zero
// means never.
func (u *KeyUse) Last() int64 { return u.lastNano.Load() }
