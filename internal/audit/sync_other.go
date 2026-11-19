//go:build !linux

// Other systems: the active file is always appended to and synced with
// File.Sync (FlushFileBuffers on Windows); a zero-filled file showed no gain
// on NTFS.

package audit

import (
	"errors"
	"os"
	"runtime"
	"syscall"
)

const prefillSupported = false

func syncData(file *os.File) error { return file.Sync() }

// Windows reports a full disk as ERROR_DISK_FULL or ERROR_HANDLE_DISK_FULL.
const (
	errorDiskFull       = syscall.Errno(112)
	errorHandleDiskFull = syscall.Errno(39)
)

// noSpace reports a write refused because the file system has no space left.
func noSpace(err error) bool {
	if runtime.GOOS == "windows" {
		return errors.Is(err, errorDiskFull) || errors.Is(err, errorHandleDiskFull)
	}
	return errors.Is(err, syscall.ENOSPC)
}
