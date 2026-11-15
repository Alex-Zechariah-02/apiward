// The demo command run as a process: Fetch stack setup and start, on the
// demo ports moved by the port offset. Each run holds the demo and every
// process it starts in one process group, stopped together.

package gatewaytest

import (
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/demoports"
)

// Bounds of the demo processes. A subcommand (setup, token, reset, events, a
// refused run) ends in seconds, so 2 minutes only stops a hung one; a stack
// gets 15 s to stop its services after its input closes and 30 s to start
// them all, each well above what a loaded CI runner needs.
const (
	demoCommandWait = 2 * time.Minute
	demoStopWait    = 15 * time.Second
	demoStartWait   = 30 * time.Second
)

// DemoTestAddress is a demo base address moved by EAT_PORT_OFFSET.
func DemoTestAddress(t *testing.T, base string) string {
	t.Helper()
	address, err := demoports.Offset(base)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

// DemoCommand runs the demo program with args and returns its combined output
// and exit code; the output, which may hold credentials, is not logged. A
// command still running after demoCommandWait is stopped with every process
// it started, and the test fails.
func DemoCommand(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(Binaries.Demo, args...)
	output := &LogBuffer{}
	cmd.Stdout, cmd.Stderr = output, output
	group, exited := startDemoGroup(t, cmd)
	select {
	case <-exited:
	case <-time.After(demoCommandWait):
		stopDemoGroup(t, group, exited)
		t.Fatalf("demo %v did not exit within %s", args, demoCommandWait)
	}
	code := cmd.ProcessState.ExitCode()
	t.Logf("demo %v: exit %d (credential output withheld)", args, code)
	return output.String(), code
}

// StartDemo runs the demo stack from dir until the test ends, and waits until
// its gateway admits requests. It returns the process, its standard input,
// which stops the stack when closed, its exit and its output. A stack that
// does not stop within demoStopWait is stopped with all its services.
func StartDemo(t *testing.T, dir, web string) (*exec.Cmd, io.WriteCloser, <-chan error, *LogBuffer) {
	t.Helper()
	cmd := exec.Command(Binaries.Demo, "run", "-dir", dir, "-web", web, "-gateway", Binaries.Plain, "-services", Binaries.Services, "-accounts", Binaries.Accounts, "-stdin")
	output := &LogBuffer{}
	cmd.Stdout, cmd.Stderr = output, output
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	group, exited := startDemoGroup(t, cmd)
	t.Cleanup(func() {
		input.Close()
		select {
		case <-exited:
		case <-time.After(demoStopWait):
			stopDemoGroup(t, group, exited)
			t.Errorf("demo cleanup exceeded its bound: %s", output)
		}
	})
	WaitFor(t, time.Now().Add(demoStartWait), "native demonstration admission", func() bool {
		return strings.Contains(output.String(), "gateway   process")
	})
	return cmd, input, exited, output
}

// startDemoGroup starts cmd in a process group released when the test ends,
// and returns the group and a channel that yields the exit once and is then
// closed.
func startDemoGroup(t *testing.T, cmd *exec.Cmd) (*processGroup, <-chan error) {
	t.Helper()
	group, err := startGroup(cmd)
	if err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		if err := group.close(); err != nil {
			t.Errorf("releasing the demo process group: %v", err)
		}
	})
	return group, exited
}

// stopDemoGroup kills the demo and every process it started, then waits for
// the demo's exit.
func stopDemoGroup(t *testing.T, group *processGroup, exited <-chan error) {
	t.Helper()
	if err := group.kill(); err != nil {
		t.Errorf("stopping the demo process group: %v", err)
	}
	<-exited
}
