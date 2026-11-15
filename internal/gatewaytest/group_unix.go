//go:build unix

// A process and every process it starts, held in a process group of its own
// so that all of them can be stopped together.

package gatewaytest

import (
	"errors"
	"os/exec"
	"syscall"
)

// processGroup is a started process and its descendants: a child stays in
// the process group of the process that starts it.
type processGroup struct {
	pid int
}

// startGroup starts cmd as the leader of a new process group.
func startGroup(cmd *exec.Cmd) (*processGroup, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &processGroup{pid: cmd.Process.Pid}, nil
}

// kill stops every process in the group at once.
func (g *processGroup) kill() error {
	return syscall.Kill(-g.pid, syscall.SIGKILL)
}

// close stops any process left in the group; a group already empty is not
// an error.
func (g *processGroup) close() error {
	if err := g.kill(); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
