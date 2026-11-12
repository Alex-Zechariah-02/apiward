// A disposable gateway deployment for tests: the programs built once per
// test binary, the deployment's files, listeners and upstream receivers, and
// control of the gateway process: start, readiness, stop and exit.

package gatewaytest

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/issuertest"
)

// Integration tests run the real gateway binary as a separate process, so a
// crash can be injected by terminating it and the database is exercised
// across real restarts. The binaries include: the gateway and the fixture
// APIs, each also with fault-injection points compiled in, and the demo tool.
var Binaries struct {
	Plain, Fault, Fixture, FixtureFault, Demo, Services, Accounts string
	race                                                          bool
}

// Issuer signs the tokens of every test. Its public key is the trust anchor
// of every test gateway unless a test configures another.
var Issuer = issuertest.New(2048)

// The gateway process's exit codes and the configuration file version it
// reads: the command-line contract the harness checks the binary against.
const (
	ExitStopped    = 0 // stopped gracefully and completely
	ExitFailed     = 1 // could not start, or the data plane failed
	ExitForced     = 2 // a second signal ended the graceful stop
	ExitIncomplete = 3 // the graceful stop did not complete
	ConfigVersion  = 1
)

// programs is the import path prefix of the gateway's programs the harness
// builds; the Fetch programs are built in the Fetch checkout.
const programs = "github.com/Alex-Zechariah-02/apiward/cmd/"

// fetchFolder is the Fetch checkout beside this repository, as in CI.
var fetchFolder = filepath.Join("..", "fetch")

// Main builds the binaries, runs the tests and removes the binaries.
// Each test package's TestMain calls it with its own block of test ports,
// first-last within 20000-29999, apart from every other package's block.
func Main(m *testing.M, first, last int) {
	if first < 20000 || first > last || last > 29999 {
		panic(fmt.Sprintf("test port block %d-%d is not within 20000-29999", first, last))
	}
	issuedPorts.first, issuedPorts.last = first, last
	dir, err := os.MkdirTemp("", "apiward-bin")
	if err != nil {
		panic(err)
	}
	Binaries.Plain = filepath.Join(dir, "apiward.exe")
	Binaries.Fault = filepath.Join(dir, "apiward-fault.exe")
	Binaries.Fixture = filepath.Join(dir, "fixture.exe")
	Binaries.FixtureFault = filepath.Join(dir, "fixture-fault.exe")
	Binaries.Demo = filepath.Join(dir, "demo.exe")
	Binaries.Services = filepath.Join(dir, "services.exe")
	Binaries.Accounts = filepath.Join(dir, "accounts.exe")
	// GATEWAY_TEST_RACE builds the gateway and fixture processes with the
	// race detector, which requires cgo and a C toolchain.
	var race []string
	if os.Getenv("GATEWAY_TEST_RACE") != "" {
		race = []string{"-race"}
		Binaries.race = true
	}
	root, err := repositoryRoot()
	fetch := filepath.Join(root, fetchFolder)
	if _, missing := os.Stat(filepath.Join(fetch, "cmd", "demo")); err == nil && missing != nil {
		err = fmt.Errorf("the Fetch repository is not checked out at %s: clone github.com/Alex-Zechariah-02/fetch there", fetch)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	builds := []struct{ out, tags, dir, pkg string }{
		{Binaries.Plain, "", root, programs + "apiward"},
		{Binaries.Fault, "faultinject", root, programs + "apiward"},
		{Binaries.Fixture, "", root, programs + "testfixture"},
		{Binaries.FixtureFault, "faultinject", root, programs + "testfixture"},
		{Binaries.Demo, "", fetch, "./cmd/demo"},
		{Binaries.Services, "", fetch, "./cmd/services"},
		{Binaries.Accounts, "", fetch, "./cmd/accounts"},
	}
	for _, build := range builds {
		args := append([]string{"build", "-tags", build.tags, "-o", build.out}, race...)
		cmd := exec.Command("go", append(args, build.pkg)...)
		cmd.Dir = build.dir
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "building %s: %v\n%s", build.pkg, err, out)
			os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// repositoryRoot is the folder of the gateway module that holds the running
// test package.
func repositoryRoot() (string, error) {
	output, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("finding the gateway module: %w", err)
	}
	return filepath.Dir(strings.TrimSpace(string(output))), nil
}

// Env is one disposable gateway deployment.
type Env struct {
	T         *testing.T
	Dir       string
	Database  string
	AuditLog  string
	PublicKey string // the issuer's verification key file
	DataAddr  string
	Admin     string
	Metrics   string
	Config    string // the gateway's configuration file
	Process   *exec.Cmd
	exited    chan error
	Output    *LogBuffer // the process's output, readable while it runs
	A, B, C   *Receiver
	session   AdminSession // the harness administrator's session, if any
	sessionMu sync.Mutex   // guards session: tests call the Admin API from several goroutines
	// interruptible starts the gateway in its own process group, so that
	// interrupt can reach it without reaching the test process.
	Interruptible bool
}

// ConfigOptions are the settings WriteConfig varies; a zero field takes the
// default its comment names.
type ConfigOptions struct {
	HeaderTimeout string         // upstream response-header timeout; default 5s
	MaxBodyBytes  int64          // global request body ceiling; default 16384
	JWT           any            // trust configuration; default the test issuer
	Audit         map[string]any // extra gateway audit settings
	Admin         map[string]any // extra gateway admin session settings
}

// NewEnv makes a deployment in a temporary directory: free listener
// addresses, the issuer's key file, three receivers and a configuration
// file. The gateway is stopped when the test ends.
func NewEnv(t *testing.T) *Env {
	t.Helper()
	dir := t.TempDir()
	e := &Env{
		T:         t,
		Dir:       dir,
		Database:  filepath.Join(dir, "state.db"),
		AuditLog:  filepath.Join(dir, "audit.log"),
		PublicKey: filepath.Join(dir, "issuer.pem"),
		DataAddr:  FreeAddr(t),
		Admin:     FreeAddr(t),
		Metrics:   FreeAddr(t),
		A:         NewReceiver(t, "A"),
		B:         NewReceiver(t, "B"),
		C:         NewReceiver(t, "C"),
	}
	if err := os.WriteFile(e.PublicKey, Issuer.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	e.WriteConfig(ConfigOptions{})
	t.Cleanup(e.Stop)
	return e
}

// Start launches the gateway and waits until both listeners accept and it
// has reported its protected admission.
func (e *Env) Start(binary string, extraEnv ...string) {
	e.T.Helper()
	e.Run(binary, extraEnv...)
	e.waitReady()
}

// Run launches the gateway's run command with e's configuration, without
// waiting for it to start.
func (e *Env) Run(binary string, extraEnv ...string) {
	e.T.Helper()
	e.Launch(binary, []string{"run", "--config", e.Config}, extraEnv...)
}

// WaitOutput waits until the running gateway has written text.
func (e *Env) WaitOutput(text string) {
	e.T.Helper()
	WaitFor(e.T, time.Now().Add(30*time.Second), fmt.Sprintf("%q in the gateway output", text), func() bool {
		return strings.Contains(e.Output.String(), text)
	})
}

// Launch stops any running gateway and starts binary with args, clearing the
// fault-injection variables so only extraEnv can set them.
func (e *Env) Launch(binary string, args []string, extraEnv ...string) {
	e.T.Helper()
	e.Stop()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(),
		"GATEWAY_FAULT=", "GATEWAY_HOLD_PATH=", "GATEWAY_HOLD_FILE=", "GATEWAY_HOLD_RELEASE=", "GATEWAY_RATE_CLOCK=", "GATEWAY_WALL_OFFSET=", "GATEWAY_AUDIT_HOLD=",
	)
	if Binaries.race {
		// Stop at the first race so it cannot be lost when the test later
		// kills the process; checkRaces reports it.
		cmd.Env = append(cmd.Env, "GORACE=halt_on_error=1")
	}
	cmd.Env = append(cmd.Env, extraEnv...)
	if e.Interruptible {
		newProcessGroup(cmd)
	}
	e.Output = &LogBuffer{}
	cmd.Stdout, cmd.Stderr = e.Output, e.Output
	if err := cmd.Start(); err != nil {
		e.T.Fatal(err)
	}
	e.Process = cmd
	e.exited = make(chan error, 1)
	go func() { e.exited <- cmd.Wait() }()
}

func (e *Env) waitReady() {
	e.T.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-e.exited:
			e.Process = nil
			e.T.Fatalf("gateway exited during startup: %v\n%s", err, e.Output)
		default:
		}
		// Listening is not readiness: the gateway reports its protected
		// admission once it has started.
		observed := strings.Contains(e.Output.String(), `"msg":"protected admission"`)
		if observed && Dialable(e.DataAddr) && Dialable(e.Admin) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.T.Fatalf("gateway not ready\n%s", e.Output)
}

// Dialable reports whether a TCP connection to addr succeeds.
func Dialable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

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
	case <-time.After(30 * time.Second):
		e.T.Fatalf("gateway did not exit\n%s", e.Output)
		return 0
	}
}
