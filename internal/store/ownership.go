// The exclusive deployment lock.

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
)

// LockDeployment uses a stable companion file: SQLite's own exclusive lock
// cannot protect a pathname while restore replaces the underlying database.
// The file is never unlinked, and the OS releases ownership after a crash.
// Like the database, it must be private (filecheck.Private).
func LockDeployment(database string) (*os.File, error) {
	path := database + ".lock"
	if err := RegularPath(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	// The opened file is checked, so a file swapped in after the path
	// check is refused too.
	info, err := file.Stat()
	if err == nil {
		err = filecheck.Private(info)
	}
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := lockFile(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("database %q is %w: %w", database, ErrHeld, err)
	}
	return file, nil
}

// CheckPrivate refuses a database whose file or companion files (the
// write-ahead log, shared memory and rollback journal SQLite keeps beside
// it) another local account could read or rewrite, or that is not a
// regular file. The gateway creates each with mode 0600; a missing
// companion is fine.
func CheckPrivate(database string) error {
	for _, path := range []string{database, database + "-wal", database + "-shm", database + "-journal"} {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file, not a link, device or directory", path)
		}
		if err := filecheck.Private(info); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}
