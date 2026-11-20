// Linux: a disk's free space as an unprivileged user sees it (statfs
// f_bavail, so ext4's root reserve does not count) and its device number,
// which tells whether two folders share a disk.

package audit

import (
	"strconv"
	"syscall"
)

// diskOf reports the free and total bytes of dir's file system and its
// identity.
func diskOf(dir string) (disk, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		return disk{}, err
	}
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return disk{}, err
	}
	return disk{free: bytesOf(fs.Bavail) * fs.Bsize, total: bytesOf(fs.Blocks) * fs.Bsize, id: strconv.FormatUint(st.Dev, 10)}, nil
}
