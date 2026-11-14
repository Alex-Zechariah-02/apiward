// The identity assertion's signing key: which file it is, whether the
// configuration may run without it, and how a missing key is reported.

package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// identityFile is the signing key's name beside the database when
// upstream.identity_key is absent; apiward install creates it.
const identityFile = "identity.pem"

// identity resolves the signing key of u. A present key file must load. A
// missing one is left for requireIdentity, so the operator commands, among
// them the install that creates it, still run.
func (cfg *nativeConfig) identity(u upstreamSettings) error {
	if u.UnsignedIdentity {
		if u.IdentityKey != nil {
			return errors.New("upstream.identity_key and upstream.unsigned_identity exclude each other")
		}
		cfg.unsigned = true
		return nil
	}
	cfg.identityKey = filepath.Join(filepath.Dir(cfg.controller.Database), identityFile)
	if u.IdentityKey != nil {
		cfg.identityKey = *u.IdentityKey
	}
	if _, err := os.Lstat(cfg.identityKey); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	signer, err := pipeline.LoadSigner(cfg.identityKey)
	if err != nil {
		return fmt.Errorf("upstream.identity_key %s: %w", cfg.identityKey, err)
	}
	cfg.signer = signer
	return nil
}

// requireIdentity refuses to serve with a missing signing key: identity
// headers are sent unsigned only when upstream.unsigned_identity says so.
func (cfg nativeConfig) requireIdentity() error {
	if cfg.unsigned || cfg.signer != nil {
		return nil
	}
	return fmt.Errorf("the identity key %s does not exist: run apiward install to create it, or set upstream.unsigned_identity to forward unsigned identity headers", cfg.identityKey)
}
