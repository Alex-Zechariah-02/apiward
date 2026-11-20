//go:build !linux && !windows

// Other systems (development only): free space is not read, so disk
// pressure never evicts and the reserve is made whatever the free space.

package audit

// diskOf reports an unknown size; dir stands for its disk.
func diskOf(dir string) (disk, error) { return disk{free: -1, total: -1, id: dir}, nil }
