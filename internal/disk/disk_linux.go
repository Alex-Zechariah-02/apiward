// Linux: a disk's free space as an unprivileged user sees it (statfs
// f_bavail, so ext4's root reserve does not count) and its device number,
// which tells whether two folders share a disk.

package disk

import (
	"strconv"
	"syscall"
)

// Of reports the free and total bytes of dir's file system and its identity.
func Of(dir string) (Space, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		return Space{}, err
	}
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return Space{}, err
	}
	return Space{Free: bytesOf(fs.Bavail) * fs.Bsize, Total: bytesOf(fs.Blocks) * fs.Bsize, ID: strconv.FormatUint(st.Dev, 10)}, nil
}
