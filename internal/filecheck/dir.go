// Durable directory entries: a new, renamed or removed name survives a
// power cut on Linux only once its directory is synced.

package filecheck

import (
	"errors"
	"os"
	"runtime"
)

// SyncDir makes the names created, renamed or removed in dir durable
// (fsync(2) on the directory). Windows cannot flush a directory handle; NTFS
// journals its entries.
func SyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}
