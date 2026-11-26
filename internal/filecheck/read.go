// Reading a checked, bounded regular file. The path is checked before it is
// opened, since opening a pipe or device can block, and again once open, so
// a file swapped in between is refused.

package filecheck

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Regular returns the information of the file at path, refusing anything
// but a regular file (a directory, pipe, device or socket) without opening
// it.
func Regular(path string) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("the path must name a regular file")
	}
	return info, nil
}

// OpenRegular opens the regular file at path after verifying it is regular
// before opening and that the opened descriptor still refers to the same file.
func OpenRegular(path string) (*os.File, os.FileInfo, error) {
	named, err := Regular(path)
	if err != nil {
		return nil, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	if !os.SameFile(named, info) {
		return nil, nil, errors.Join(errors.New("the file was replaced while it was opened"), file.Close())
	}
	return file, info, nil
}

// Read reads the regular file at path, refusing one larger than limit bytes
// unread, after check, when given, accepted the opened file's information.
func Read(path string, limit int64, check func(os.FileInfo) error) ([]byte, error) {
	file, info, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if check != nil {
		if err := check(info); err != nil {
			return nil, err
		}
	}
	// Refused before any read; the bounded read still stops a file that grows.
	if info.Size() > limit {
		return nil, fmt.Errorf("the file is larger than %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("the file is larger than %d bytes", limit)
	}
	return data, nil
}
