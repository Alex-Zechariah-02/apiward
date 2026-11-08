//go:build !windows

// Interrupting a gateway process outside Windows: SIGINT to the process.

package gatewaytest

import (
	"os"
	"os/exec"
	"testing"
)

// newProcessGroup needs nothing outside Windows: a signal reaches one
// process.
func newProcessGroup(*exec.Cmd) {}

// Interrupt sends SIGINT to the process of cmd.
func Interrupt(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("interrupting process %d: %v", cmd.Process.Pid, err)
	}
}
