//go:build !windows

// Other systems: an open file never blocks its rename or deletion, so audit
// files are opened for reading as usual.

package audit

import "os"

// OpenShared opens an audit file for reading.
func OpenShared(path string) (*os.File, error) { return os.Open(path) }
