// Linux: a disk's free space as an unprivileged user sees it (statfs
// f_bavail, so ext4's root reserve does not count) and its device number,
// which tells whether two folders share a disk.

package disk

import (
	"math"
	"math/bits"
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
	return Space{Free: mulBytes(fs.Bavail, fs.Bsize), Total: mulBytes(fs.Blocks, fs.Bsize), ID: strconv.FormatUint(st.Dev, 10)}, nil
}

// mulBytes multiplies a block count by a block size without overflowing int64.
func mulBytes(blocks uint64, bsize int64) int64 {
	if bsize <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(blocks, uint64(bsize))
	if hi != 0 {
		return math.MaxInt64
	}
	return bytesOf(lo)
}
