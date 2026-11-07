// Real-process harness: the gateway and the recording upstream run as their own processes, built once per test binary.

package migrate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// builds holds the binaries the differential tests run, built on first use.
var builds struct {
	once             sync.Once
	dir              string
	gateway, fixture string
	err              error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if builds.dir != "" {
		os.RemoveAll(builds.dir)
	}
	os.Exit(code)
}

// binaries builds the gateway and the recording upstream once.
func binaries(t *testing.T) (string, string) {
	t.Helper()
	builds.once.Do(func() {
		if builds.dir, builds.err = os.MkdirTemp("", "migrate-bin"); builds.err != nil {
			return
		}
		builds.gateway, builds.fixture = filepath.Join(builds.dir, "gateway.exe"), filepath.Join(builds.dir, "fixture.exe")
		for out, pkg := range map[string]string{builds.gateway: "../../cmd/gateway", builds.fixture: "../../cmd/testfixture"} {
			if output, err := exec.Command("go", "build", "-o", out, pkg).CombinedOutput(); err != nil {
				builds.err = fmt.Errorf("building %s: %v\n%s", pkg, err, output)
				return
			}
		}
	})
	if builds.err != nil {
		t.Fatal(builds.err)
	}
	return builds.gateway, builds.fixture
}

// freeAddr returns a loopback address no listener holds now.
func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func dialable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		conn.Close()
	}
	return err == nil
}

// output collects a process's output while it runs.
type output struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

// start runs a process until the test ends and waits until ready holds.
func start(t *testing.T, name string, args []string, ready func(string) bool) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(name, args...)
	out := &output{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-exited
	})
	deadline := time.Now().Add(30 * time.Second)
	for !ready(out.String()) {
		select {
		case err := <-exited:
			t.Fatalf("%s exited: %v\n%s", filepath.Base(name), err, out)
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not ready\n%s", filepath.Base(name), out)
		}
	}
	return cmd
}

// upstream is the recording fixture API: every request it receives leaves a receipt.
type upstream struct {
	addr, control, secret string
	cmd                   *exec.Cmd
}

func startUpstream(t *testing.T) *upstream {
	t.Helper()
	_, fixture := binaries(t)
	key := make([]byte, 32)
	rand.Read(key)
	u := &upstream{addr: freeAddr(t), control: freeAddr(t), secret: hex.EncodeToString(key)}
	secretFile := filepath.Join(t.TempDir(), "control.secret")
	if err := os.WriteFile(secretFile, []byte(u.secret), 0o600); err != nil {
		t.Fatal(err)
	}
	u.cmd = start(t, fixture, []string{"-service", "orders", "-listen", u.addr, "-control", u.control, "-secret-file", secretFile},
		func(string) bool { return dialable(u.addr) && dialable(u.control) })
	return u
}

// received is how many requests the upstream has recorded.
func (u *upstream) received(t *testing.T) int {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, "http://"+u.control+"/receipts", http.NoBody)
	request.Header.Set("Authorization", "Bearer "+u.secret)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body struct{ Receipts []json.RawMessage }
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("receipts: %d %v", response.StatusCode, err)
	}
	return len(body.Receipts)
}

// stop ends the upstream, so forwarded requests fail.
func (u *upstream) stop() {
	u.cmd.Process.Kill()
}

// admin is a session on the gateway's Admin API.
type admin struct {
	t                  *testing.T
	addr, cookie, csrf string
}

// send makes one Admin API request and fails the test unless it answers wanted.
func (a *admin) send(method, path string, body any, wanted int, header ...string) (http.Header, []byte) {
	a.t.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	request, _ := http.NewRequest(method, "http://"+a.addr+path, reader)
	request.Header.Set("Origin", "http://"+a.addr)
	request.Header.Set("Content-Type", "application/json")
	if a.cookie != "" {
		request.Header.Set("Cookie", a.cookie)
		request.Header.Set("X-CSRF-Token", a.csrf)
	}
	for i := 0; i+1 < len(header); i += 2 {
		request.Header.Set(header[i], header[i+1])
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		a.t.Fatal(err)
	}
	defer response.Body.Close()
	reply, _ := io.ReadAll(response.Body)
	if response.StatusCode != wanted {
		a.t.Fatalf("%s %s: %d %s", method, path, response.StatusCode, reply)
	}
	if strings.HasPrefix(path, "/admin/session") {
		for _, cookie := range response.Cookies() {
			a.cookie = cookie.Name + "=" + cookie.Value
		}
		var session struct {
			CSRF string `json:"csrf_token"`
		}
		json.Unmarshal(reply, &session)
		a.csrf = session.CSRF
	}
	return response.Header, reply
}
