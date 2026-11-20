// Windows: audit files are opened for reading with delete sharing, so a
// read never blocks the writer's rename at a rotation, or the archiver's
// move or deletion; os.Open shares read and write access only.

package audit

import (
	"os"
	"syscall"
)

// OpenShared opens an audit file for reading. Renaming or deleting it while
// it is open succeeds; the open handle keeps reading the same file.
func OpenShared(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	share := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE)
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, share, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
