// Windows: a disk's free space for the gateway's user (quotas included)
// and its volume name, which tells whether two folders share a disk.

package audit

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// diskOf reports the free and total bytes of dir's volume and its identity.
func diskOf(dir string) (disk, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return disk{}, err
	}
	name, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return disk{}, err
	}
	var free, total, unused uint64
	if err := windows.GetDiskFreeSpaceEx(name, &free, &total, &unused); err != nil {
		return disk{}, err
	}
	return disk{free: bytesOf(free), total: bytesOf(total), id: strings.ToLower(filepath.VolumeName(abs))}, nil
}
