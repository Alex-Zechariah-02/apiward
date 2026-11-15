// The owner check of trusted files where ownership is not a Unix user ID:
// access is set by the system's own controls, which the operator owns.

//go:build !unix

package forward

import "os"

func checkOwner(os.FileInfo) error { return nil }
