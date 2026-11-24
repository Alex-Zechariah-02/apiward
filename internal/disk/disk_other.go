//go:build !linux && !windows

// Other systems (development only): free space is not read, so disk
// pressure never evicts and the reserve is made whatever the free space.

package disk

// Of reports an unknown size; dir stands for its disk.
func Of(dir string) (Space, error) { return Space{Free: -1, Total: -1, ID: dir}, nil }
