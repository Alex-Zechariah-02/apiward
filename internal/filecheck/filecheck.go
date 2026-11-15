// Mode and owner checks of the files the gateway trusts or keeps secret,
// shared by the store, the forwarder and the token verifier.

package filecheck

import (
	"errors"
	"os"
	"runtime"
)

// Secret refuses a file whose mode lets the group or others read it, on
// systems where the mode means that: a private key or the database.
func Secret(info os.FileInfo) error {
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("the file must not be accessible to the group or others (chmod 600)")
	}
	return nil
}

// Trusted refuses a trust anchor (a CA pin or a token verification key)
// another local account could rewrite to make the gateway trust what it
// signs: on Unix it must not be writable by the group or others and must
// belong to the gateway's user or root. Windows grants access by ACL, which
// the operator sets (docs/keys.md).
func Trusted(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("the file must not be writable by the group or others (chmod go-w)")
	}
	return owner(info)
}

// Private refuses a file of the gateway's own state (the database, its
// lock and companion files) that another local account could read or
// rewrite: Secret's mode, and on Unix the gateway's user or root as owner.
func Private(info os.FileInfo) error {
	if err := Secret(info); err != nil {
		return err
	}
	return owner(info)
}
