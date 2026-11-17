// The identity assertion's signing key, created by install so a new
// deployment signs the identity it forwards from its first request.

package operator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// createIdentityKey writes a new ECDSA P-256 key as one PKCS #8 PEM block,
// readable only by its owner, at path unless a file is already there (an
// operator's own key is kept). It reports whether it wrote one; an empty
// path (signing turned off) writes nothing.
func createIdentityKey(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, err
	}
	// The key is written whole beside path and linked into place, so a
	// command killed while writing leaves no partial key that every later
	// command would refuse; the link never replaces a key already there.
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".identity-*.tmp")
	if err != nil {
		return false, err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		return false, errors.Join(err, file.Close())
	}
	if err := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return false, errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return false, errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	if err := os.Link(temporary, path); err != nil {
		return false, err
	}
	return true, syncDir(dir)
}
