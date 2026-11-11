// The operator's upstream network settings: whether public addresses are
// allowed, and the TLS profiles (CA pin, client certificate) upstream URLs
// name by ID. Loaded from files at start and on key reload.

package forward

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

const (
	// MaxProfiles bounds the TLS profiles of one operator file.
	MaxProfiles = 32
	// maxPEMBytes bounds each certificate or key file.
	maxPEMBytes = 64 << 10
	// maxPinned bounds the certificates of one CA file.
	maxPinned = 16
	// minRSABits is the smallest RSA client key accepted.
	minRSABits = 2048
)

// ProfileSettings is one TLS profile of the operator file.
type ProfileSettings struct {
	ID                    string `json:"id"`
	CAFile                string `json:"ca_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
	ClientKeyFile         string `json:"client_key_file"`
}

// ProfileInfo describes a loaded profile without its file paths or keys.
type ProfileInfo struct {
	ID                string     `json:"id"`
	CAPinned          bool       `json:"ca_pinned"`
	ClientCertificate bool       `json:"client_certificate"`
	ExpiresAt         *time.Time `json:"client_certificate_expires_at"`
}

// Network is a loaded, immutable set of upstream network settings. It
// satisfies compile.Network.
type Network struct {
	public   bool
	profiles map[string]*profile
	// sessions holds each profile's TLS session cache, "" for endpoints
	// without a profile; empty when resumption is off.
	sessions map[string]*sessionCache
}

type profile struct {
	roots       *x509.CertPool // nil: the system roots
	certificate *tls.Certificate
	info        ProfileInfo
}

// LoadNetwork reads every profile's files. It fails on the first profile
// that is invalid, naming it; it never returns a partial set. TLS sessions
// to upstreams are resumed for at most sessionLifetime; 0 turns resumption
// off.
func LoadNetwork(public bool, settings []ProfileSettings, sessionLifetime time.Duration) (*Network, error) {
	if len(settings) > MaxProfiles {
		return nil, fmt.Errorf("upstream.tls_profiles holds more than %d profiles", MaxProfiles)
	}
	n := &Network{public: public, profiles: map[string]*profile{}, sessions: map[string]*sessionCache{}}
	for i, s := range settings {
		if err := policy.CheckID(s.ID, "id"); err != nil {
			return nil, fmt.Errorf("upstream.tls_profiles[%d].id is not a valid identifier", i)
		}
		if n.profiles[s.ID] != nil {
			return nil, fmt.Errorf("upstream.tls_profiles[%d].id %q is repeated", i, s.ID)
		}
		p, err := loadProfile(s)
		if err != nil {
			return nil, fmt.Errorf("upstream TLS profile %q: %w", s.ID, err)
		}
		n.profiles[s.ID] = p
	}
	if sessionLifetime > 0 {
		n.sessions[""] = newSessionCache(sessionLifetime)
		for id := range n.profiles {
			n.sessions[id] = newSessionCache(sessionLifetime)
		}
	}
	return n, nil
}

func loadProfile(s ProfileSettings) (*profile, error) {
	p := &profile{info: ProfileInfo{ID: s.ID}}
	if s.CAFile != "" {
		roots, err := loadRoots(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		p.roots, p.info.CAPinned = roots, true
	}
	if (s.ClientCertificateFile == "") != (s.ClientKeyFile == "") {
		return nil, errors.New("client_certificate_file and client_key_file must be set together")
	}
	if s.ClientCertificateFile == "" {
		return p, nil
	}
	certificate, err := LoadCertificate(s.ClientCertificateFile, s.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	expires := certificate.Leaf.NotAfter.UTC()
	p.certificate, p.info.ClientCertificate, p.info.ExpiresAt = certificate, true, &expires
	return p, nil
}

// readPEMFile reads a bounded file at an absolute path.
func readPEMFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("the path must be absolute")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxPEMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPEMBytes {
		return nil, fmt.Errorf("the file is larger than %d bytes", maxPEMBytes)
	}
	return data, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	data, err := readPEMFile(path)
	if err != nil {
		return nil, err
	}
	roots, count := x509.NewCertPool(), 0
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("holds a %s block; only CERTIFICATE blocks are allowed", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		roots.AddCert(certificate)
		count++
	}
	if count == 0 || count > maxPinned {
		return nil, fmt.Errorf("must hold 1 to %d certificates", maxPinned)
	}
	return roots, nil
}

// LoadCertificate reads a certificate chain (leaf first) and its private key
// from absolute paths: the key a PKCS #8 RSA key of at least 2,048 bits or
// an ECDSA P-256 key, in a file the group and others cannot read on Unix.
// The returned certificate's Leaf is parsed.
func LoadCertificate(certificateFile, keyFile string) (*tls.Certificate, error) {
	chain, err := readPEMFile(certificateFile)
	if err != nil {
		return nil, fmt.Errorf("certificate file: %w", err)
	}
	if err := CheckKeyFile(keyFile); err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	key, err := readPEMFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	if block, _ := pem.Decode(key); block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("the key file must hold a PKCS #8 PRIVATE KEY block")
	}
	certificate, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, errors.New("the certificate and key do not form a pair")
	}
	switch k := certificate.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("an RSA key must have at least %d bits", minRSABits)
		}
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("an ECDSA key must use P-256")
		}
	default:
		return nil, errors.New("the key must be RSA or ECDSA P-256")
	}
	return &certificate, nil
}

// CheckKeyFile refuses a key file whose mode lets the group or others read
// it, on systems where the mode means that.
func CheckKeyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("the key file must not be accessible to the group or others (chmod 600)")
	}
	return nil
}

// Public reports whether upstreams may use public addresses.
func (n *Network) Public() bool { return n.public }

// Has reports whether a TLS profile with that ID is loaded.
func (n *Network) Has(id string) bool { return n.profiles[id] != nil }

// Profiles describes the loaded profiles, by ID.
func (n *Network) Profiles() []ProfileInfo {
	items := make([]ProfileInfo, 0, len(n.profiles))
	for _, p := range n.profiles {
		items = append(items, p.info)
	}
	slices.SortFunc(items, func(a, b ProfileInfo) int { return strings.Compare(a.ID, b.ID) })
	return items
}

// clientConfig is the TLS configuration of a connection to e: TLS 1.2 or
// later, HTTP/1.1 only, the certificate verified for e's host against the
// profile's CA pin or the system roots, the profile's client certificate if
// it has one, and the profile's session cache when resumption is on.
func (n *Network) clientConfig(e *compile.Endpoint) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: e.ServerName(), NextProtos: []string{"http/1.1"}}
	if cache := n.sessions[e.Profile()]; cache != nil {
		config.ClientSessionCache = cache
	}
	if e.Profile() == "" {
		return config, nil
	}
	p := n.profiles[e.Profile()]
	if p == nil {
		return nil, errProfileMissing
	}
	config.RootCAs = p.roots
	if p.certificate != nil {
		config.Certificates = []tls.Certificate{*p.certificate}
	}
	return config, nil
}
