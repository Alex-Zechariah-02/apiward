// The controlled fixture APIs as separate processes: start, calls to their
// control endpoints, receipts and state.

package gatewaytest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fixture "github.com/Alex-Zechariah-02/apiward/internal/testfixture"
)

var fixtureNames = []string{"orders", "inventory", "reports"}

// FixtureProcess is one fixture API running as its own process.
type FixtureProcess struct {
	T       *testing.T
	Name    string
	Addr    string // API listener, reached only through the gateway
	Control string // receipts, state and reset; requires the secret
	Secret  string
	output  *bytes.Buffer
}

// StartFixtures runs the three fixture APIs on loopback, each with its own
// control secret, and stops them when the test ends.
func StartFixtures(t *testing.T) map[string]*FixtureProcess {
	t.Helper()
	return StartFixtureSet(t, Binaries.Fixture)
}

// StartFixtureSet starts one process of binary per fixture, each with its own
// control secret, and stops them when the test ends.
func StartFixtureSet(t *testing.T, binary string, extraEnv ...string) map[string]*FixtureProcess {
	t.Helper()
	dir := t.TempDir()
	fixtures := map[string]*FixtureProcess{}
	for _, name := range fixtureNames {
		secret := make([]byte, 32)
		rand.Read(secret)
		f := &FixtureProcess{
			T:       t,
			Name:    name,
			Addr:    FreeAddr(t),
			Control: FreeAddr(t),
			Secret:  hex.EncodeToString(secret),
			output:  &bytes.Buffer{},
		}
		secretFile := filepath.Join(dir, name+".secret")
		if err := os.WriteFile(secretFile, []byte(f.Secret), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "-service", name, "-listen", f.Addr, "-control", f.Control, "-secret-file", secretFile)
		cmd.Env = append(os.Environ(), "FIXTURE_FAULT=")
		cmd.Env = append(cmd.Env, extraEnv...)
		if Binaries.race {
			cmd.Env = append(cmd.Env, "GORACE=halt_on_error=1")
		}
		newProcessGroup(cmd)
		cmd.Stdout, cmd.Stderr = f.output, f.output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		t.Cleanup(func() {
			Interrupt(t, cmd)
			select {
			case err := <-exited:
				if err != nil {
					t.Errorf("fixture %s did not stop cleanly: %v\n%s", name, err, f.output)
				}
			case <-time.After(6 * time.Second):
				cmd.Process.Kill()
				<-exited
				t.Errorf("fixture %s shutdown exceeded its bound", name)
			}
			if strings.Contains(f.output.String(), "WARNING: DATA RACE") {
				t.Errorf("race detected in fixture %s:\n%s", name, f.output)
			}
		})
		deadline := time.Now().Add(10 * time.Second)
		for !Dialable(f.Addr) || !Dialable(f.Control) {
			if time.Now().After(deadline) {
				t.Fatalf("fixture %s not ready\n%s", name, f.output)
			}
			time.Sleep(20 * time.Millisecond)
		}
		fixtures[name] = f
	}
	return fixtures
}

// Call sends a request to the fixture's control listener, with secret as its
// bearer token when not empty, and returns the status and body.
func (f *FixtureProcess) Call(method, path, secret string) (int, []byte) {
	f.T.Helper()
	req, _ := http.NewRequest(method, "http://"+f.Control+path, http.NoBody)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		f.T.Fatalf("fixture %s control %s: %v", f.Name, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// Receipts reads every request the fixture has received.
func (f *FixtureProcess) Receipts() []fixture.Receipt {
	f.T.Helper()
	code, data := f.Call(http.MethodGet, "/receipts", f.Secret)
	var body struct{ Receipts []fixture.Receipt }
	if code != http.StatusOK || json.Unmarshal(data, &body) != nil {
		f.T.Fatalf("fixture %s receipts: %d %s", f.Name, code, data)
	}
	return body.Receipts
}

// State reads the fixture's current state.
func (f *FixtureProcess) State() fixture.State {
	f.T.Helper()
	return f.DecodeState(f.Call(http.MethodGet, "/state", f.Secret))
}

// DecodeState decodes a state reply, failing the test on any other answer.
func (f *FixtureProcess) DecodeState(code int, data []byte) fixture.State {
	f.T.Helper()
	var s fixture.State
	if code != http.StatusOK || json.Unmarshal(data, &s) != nil {
		f.T.Fatalf("fixture %s state: %d %s", f.Name, code, data)
	}
	return s
}

// ReceiptCounts is the number of receipts each fixture holds.
func ReceiptCounts(fixtures map[string]*FixtureProcess) map[string]int {
	counts := map[string]int{}
	for name, f := range fixtures {
		counts[name] = len(f.Receipts())
	}
	return counts
}
