// The demo command run as a process: Fetch stack setup and start, on the
// demo ports moved by the port offset.

package gatewaytest

import (
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/demoports"
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
// and exit code; the output, which may hold credentials, is not logged.
func DemoCommand(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(Binaries.Demo, args...)
	output, err := cmd.CombinedOutput()
	if err != nil && cmd.ProcessState == nil {
		t.Fatal(err)
	}
	code := cmd.ProcessState.ExitCode()
	t.Logf("demo %v: exit %d (credential output withheld)", args, code)
	return string(output), code
}

// StartDemo runs the demo stack from dir until the test ends, and waits until
// its gateway admits requests. It returns the process, its standard input,
// which stops the stack when closed, its exit and its output.
func StartDemo(t *testing.T, dir string) (*exec.Cmd, io.WriteCloser, <-chan error, *LogBuffer) {
	t.Helper()
	cmd := exec.Command(Binaries.Demo, "run", "-dir", dir, "-gateway", Binaries.Plain, "-services", Binaries.Services, "-accounts", Binaries.Accounts, "-stdin")
	output := &LogBuffer{}
	cmd.Stdout, cmd.Stderr = output, output
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		input.Close()
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-exited
			t.Errorf("demo cleanup exceeded its bound: %s", output)
		}
	})
	WaitFor(t, time.Now().Add(30*time.Second), "native demonstration admission", func() bool {
		return strings.Contains(output.String(), "gateway   process")
	})
	return cmd, input, exited, output
}
