// A file system's free and total space (-1 when unknown) and an identity
// shared by folders on the same file system.

package disk

import "math"

// Space reports a file system's free and total bytes (-1 when unknown) and
// an identity shared by folders on the same file system.
type Space struct {
	Free, Total int64
	ID          string
}

// Below reports whether the disk's free space is under share of its size,
// or under floor bytes; never for an unknown size.
func (d Space) Below(share float64, floor int64) bool {
	if d.Total <= 0 {
		return false
	}
	return float64(d.Free) < share*float64(d.Total) || d.Free < floor
}

func bytesOf(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}
