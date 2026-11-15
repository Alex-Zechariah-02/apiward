// The owner check of trusted files on Unix: the file's owner must be the
// gateway's user or root.

//go:build unix

package forward

import (
	"errors"
	"os"
	"syscall"
)

func checkOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("the file's owner cannot be read")
	}
	if stat.Uid != 0 && int(stat.Uid) != os.Getuid() {
		return errors.New("the file must belong to the gateway's user or root")
	}
	return nil
}
