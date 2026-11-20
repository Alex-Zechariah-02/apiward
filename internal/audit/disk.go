// A disk as the archiver sees it: free and total bytes (-1 when unknown)
// and an identity shared by the folders on the same file system.

package audit

import "math"

type disk struct {
	free, total int64
	id          string
}

// below reports whether the disk's free space is under share of its size,
// or under floor bytes; never for an unknown size.
func (d disk) below(share float64, floor int64) bool {
	if d.total <= 0 {
		return false
	}
	return float64(d.free) < share*float64(d.total) || d.free < floor
}

// bytesOf converts a file system's byte count, capped at the largest int64.
func bytesOf(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}
