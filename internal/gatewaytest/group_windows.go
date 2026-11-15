// A process and every process it starts, held in a Windows job object so
// that all of them can be stopped together.

package gatewaytest

import (
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// processGroup is a started process and its descendants. The Fetch demo
// starts each child in a console group of its own, so only a job holds them
// all; a child inherits the job of the process that starts it.
type processGroup struct {
	job windows.Handle
}

// startGroup starts cmd inside a new job. The job kills every process still
// in it when its last handle closes, so close also stops what kill missed.
func startGroup(cmd *exec.Cmd) (*processGroup, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("creating a job object: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("setting the job limits: %w", err)
	}
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		windows.CloseHandle(process)
	}
	if err != nil {
		cmd.Process.Kill()
		windows.CloseHandle(job)
		return nil, fmt.Errorf("adding process %d to its job: %w", cmd.Process.Pid, err)
	}
	return &processGroup{job: job}, nil
}

// kill stops every process in the group at once.
func (g *processGroup) kill() error {
	return windows.TerminateJobObject(g.job, 1)
}

// close releases the job, which stops any process still in it.
func (g *processGroup) close() error {
	return windows.CloseHandle(g.job)
}
