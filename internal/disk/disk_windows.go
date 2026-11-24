// Windows: a disk's free space for the gateway's user (quotas included)
// and its volume name, which tells whether two folders share a disk.

package disk

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Of reports the free and total bytes of dir's volume and its identity.
func Of(dir string) (Space, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Space{}, err
	}
	name, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return Space{}, err
	}
	var free, total, unused uint64
	if err := windows.GetDiskFreeSpaceEx(name, &free, &total, &unused); err != nil {
		return Space{}, err
	}
	return Space{Free: bytesOf(free), Total: bytesOf(total), ID: strings.ToLower(filepath.VolumeName(abs))}, nil
}
