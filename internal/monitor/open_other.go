//go:build !windows

// Other systems: an open file never blocks its rename or deletion, so
// security log files are opened as usual.

package monitor

import "os"

// openLog opens a security log file for reading.
func openLog(path string) (*os.File, error) { return os.Open(path) }
