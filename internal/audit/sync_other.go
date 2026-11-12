//go:build !linux

// Other systems: the active file is always appended to and synced with
// File.Sync (FlushFileBuffers on Windows); a zero-filled file showed no gain
// on NTFS.

package audit

import "os"

const prefillSupported = false

func syncData(file *os.File) error { return file.Sync() }
