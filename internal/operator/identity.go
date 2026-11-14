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
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	if err := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return false, errors.Join(err, file.Close(), os.Remove(path))
	}
	if err := file.Sync(); err != nil {
		return false, errors.Join(err, file.Close(), os.Remove(path))
	}
	return true, file.Close()
}
