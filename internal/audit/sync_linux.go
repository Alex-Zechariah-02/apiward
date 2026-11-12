// Linux: the active file may be zero-filled and synced with fdatasync.

package audit

import (
	"os"
	"syscall"
)

const prefillSupported = true

// syncData flushes the file's data and only the metadata needed to read it
// back (fdatasync(2)); a write into blocks already written and synced
// changes neither size nor allocation, so no journal commit is needed.
func syncData(file *os.File) error {
	conn, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var syncErr error
	err = conn.Control(func(fd uintptr) {
		for {
			syncErr = syscall.Fdatasync(int(fd))
			if syncErr != syscall.EINTR {
				return
			}
		}
	})
	if err != nil {
		return err
	}
	if syncErr != nil {
		return &os.PathError{Op: "fdatasync", Path: file.Name(), Err: syncErr}
	}
	return nil
}
