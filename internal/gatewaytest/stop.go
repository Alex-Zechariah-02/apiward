// Stopping a test gateway: abruptly at any point, gracefully so that every
// queued record is written, and waiting for a gateway that ends by itself.

package gatewaytest

import (
	"strings"
	"time"
)

// Stop terminates the gateway abruptly. The design must tolerate this at any
// point, so tests never rely on a graceful shutdown.
func (e *Env) Stop() {
	e.sessionMu.Lock()
	e.session = AdminSession{}
	e.sessionMu.Unlock()
	if e.Process == nil {
		return
	}
	e.Process.Process.Kill()
	// A killed process always exits, so this wait needs no bound.
	<-e.exited
	e.Process = nil
	e.checkRaces()
}

// checkRaces fails the test if the race detector reported anything in the
// gateway process. Call only after the process has exited, so the output is
// complete and no longer being written.
func (e *Env) checkRaces() {
	e.T.Helper()
	if strings.Contains(e.Output.String(), "WARNING: DATA RACE") {
		e.T.Errorf("race detected in gateway process:\n%s", e.Output)
	}
}

// WaitExit waits for a gateway that is expected to terminate itself.
func (e *Env) WaitExit() int {
	e.T.Helper()
	select {
	case <-e.exited:
		code := e.Process.ProcessState.ExitCode()
		e.Process = nil
		e.checkRaces()
		return code
	// Well above the gateway's own stop bounds; it only stops a hung exit.
	case <-time.After(30 * time.Second):
		e.T.Fatalf("gateway did not exit\n%s", e.Output)
		return 0
	}
}

// Shutdown stops the gateway gracefully and requires a complete stop, so
// every record it queued is in the audit file and no writer runs after it.
// The gateway must have been started Interruptible.
func (e *Env) Shutdown() {
	e.T.Helper()
	if e.Process == nil {
		return
	}
	if !e.Interruptible {
		e.T.Fatal("Shutdown needs a gateway started Interruptible")
	}
	e.sessionMu.Lock()
	e.session = AdminSession{}
	e.sessionMu.Unlock()
	Interrupt(e.T, e.Process)
	if code := e.WaitExit(); code != ExitStopped {
		e.T.Fatalf("graceful stop ended with exit status %d\n%s", code, e.Output)
	}
}
