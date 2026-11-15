// Operator file checks, digests and exclusive writes.

package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// checkDatabaseFile opens a snapshot with the gateway's settings in rollback
// journal mode, so it is a single self-contained file, and runs the full
// integrity check and the schema checks.
func checkDatabaseFile(path string) error {
	db, err := store.Connect(path, "DELETE")
	if err != nil {
		return err
	}
	defer db.Close()
	var check string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		return fmt.Errorf("integrity check failed: %v %s", err, check)
	}
	return store.Verify(db)
}

func sameFile(a, b string) bool {
	first, err1 := os.Stat(a)
	second, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(first, second)
}

// fileDigest reads a regular file through one handle and returns its
// SHA-256, size and identity, which samePath checks again later.
func fileDigest(path string) (string, int64, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, nil, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, nil, fmt.Errorf("%s must be a regular file", path)
	}
	if err := samePath(path, info); err != nil {
		return "", 0, nil, err
	}
	sum := sha256.New()
	size, err := io.Copy(sum, file)
	if err != nil {
		return "", 0, nil, err
	}
	return hex.EncodeToString(sum.Sum(nil)), size, info, nil
}

// samePath refuses when path no longer names the file info describes: a
// link or rename put another file there after it was checked or opened.
func samePath(path string, info os.FileInfo) error {
	now, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(now, info) {
		return fmt.Errorf("%s was replaced while the command used it", path)
	}
	return nil
}

// readBounded reads a file of at most limit bytes and refuses a larger one.
func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// syncDir makes new names in dir durable: on Linux a new directory entry
// survives a power cut only once the directory is synced (fsync(2)).
// Windows cannot flush a directory handle; NTFS journals its entries.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}

// writeNewFile writes value as JSON to a file that must not exist yet.
func writeNewFile(path string, value any) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	_, err = file.Write(append(data, '\n'))
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		os.Remove(path)
	}
	return err
}
