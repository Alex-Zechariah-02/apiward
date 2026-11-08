// The Fetch demo stack a test owns: set up and started by the demo command,
// its administrator enrolled and its baseline confirmed, and the calls the
// stack scenarios make to its accounts, services and service controls.

package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/services"
)

type fetchStack struct {
	t        *testing.T
	e        *env
	dir      string
	secret   []byte // the services' control secret
	password string // the enrolled administrator's
	root     adminSession
	baseline policy.Policy
	revision int64 // the confirmed baseline's
	input    io.WriteCloser
	exited   <-chan error
}

// startFetchStack sets up and starts the demo stack on its fixed ports, enrols
// root, establishes the deny-all genesis and confirms the baseline.
func startFetchStack(t *testing.T) *fetchStack {
	parent := t.TempDir()
	web := filepath.Join(parent, "web")
	for _, page := range []string{"admin", "demo"} {
		if err := os.MkdirAll(filepath.Join(web, page), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(web, page, "index.html"), []byte("owned stack test page"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(parent, "state")
	install, code := demoCommand(t, "setup", "-dir", dir, "-web", web, "-gateway", binaries.plain, "-admin", "root")
	if code != 0 {
		t.Fatal("Fetch setup failed")
	}
	s := &fetchStack{t: t, dir: dir, password: testPassword()}
	var output *logBuffer
	_, s.input, s.exited, output = startDemo(t, dir)
	e := &env{t: t, dir: dir, database: filepath.Join(dir, "state.db"), auditLog: filepath.Join(dir, "audit.log"), dataAddr: demoTestAddress(t, "127.0.0.2:9480"), admin: demoTestAddress(t, "127.0.0.1:9440"), output: output}
	s.e = e
	if code, body := e.enrol("root", enrolmentSecret(t, install), s.password); code != 201 {
		t.Fatalf("enrol: %d %s", code, body)
	}
	s.root = e.mustLogin("root", s.password)
	s.baseline = s.loadPolicy("baseline.json")
	code, first, body := e.stage(s.root, s.loadPolicy("deny-all.json"), `"r0"`, "fetch-stack-genesis")
	if code != 201 {
		t.Fatalf("stage genesis: %d %s", code, body)
	}
	if code, _ := e.establish(s.root, "/admin/genesis", first.Candidate.ID, first.Candidate.Checksum); code != 200 {
		t.Fatalf("genesis: %d", code)
	}
	s.revision = e.confirmPolicy(s.root, s.baseline, 1, "fetch-stack-baseline").Revision
	if s.revision == 0 {
		t.Fatal("baseline was not confirmed")
	}
	secret, err := os.ReadFile(filepath.Join(dir, "service.secret"))
	if err != nil {
		t.Fatal(err)
	}
	s.secret = secret
	return s
}

// loadPolicy reads one of the policies setup wrote.
func (s *fetchStack) loadPolicy(name string) policy.Policy {
	s.t.Helper()
	data, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		s.t.Fatal(err)
	}
	p, err := policy.DecodePolicy(data)
	if err != nil {
		s.t.Fatal(err)
	}
	return p
}

// call sends a request through the gateway with token (empty: none) and
// requires status want and a request ID.
func (s *fetchStack) call(method, path, body, token string, want int) (*http.Response, string) {
	s.t.Helper()
	headers := []string{}
	if token != "" {
		headers = append(headers, "Authorization", "Bearer "+token)
	}
	response, reply := s.e.exchange(method, path, "application/json", body, headers...)
	if response.StatusCode != want || response.Header.Get("X-Request-Id") == "" {
		s.t.Fatalf("%s %s: status %d, want %d (response withheld for credential safety)", method, path, response.StatusCode, want)
	}
	return response, reply
}

// login signs a demo account in through Fetch Accounts and returns its token.
func (s *fetchStack) login(email string) string {
	s.t.Helper()
	_, body := s.call("POST", "/accounts/login", string(mustJSON(map[string]string{"email": email, "password": "FetchDemo2026!"})), "", 200)
	var reply struct {
		Token string `json:"token"`
	}
	if json.Unmarshal([]byte(body), &reply) != nil || reply.Token == "" {
		s.t.Fatal("Accounts returned no token")
	}
	return reply.Token
}

// control reads path from the control listener of the service at index.
func (s *fetchStack) control(index int, path string) []byte {
	s.t.Helper()
	request, _ := http.NewRequest("GET", "http://"+demoTestAddress(s.t, fmt.Sprintf("127.0.0.1:%d", 9601+index))+path, nil)
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(s.secret)))
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		s.t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 {
		s.t.Fatal("service control failed")
	}
	return data
}

// receiptCount is the number of receipts the service at index recorded.
func (s *fetchStack) receiptCount(index int) int {
	s.t.Helper()
	var view struct {
		Receipts []services.Receipt `json:"receipts"`
	}
	if json.Unmarshal(s.control(index, "/receipts"), &view) != nil {
		s.t.Fatal("invalid receipts")
	}
	return len(view.Receipts)
}

// refused proves a gateway refusal by the service's own receipts: the
// service at index recorded nothing and the answer carries no X-Service.
func (s *fetchStack) refused(index int, method, path, body, token string, want int) {
	s.t.Helper()
	count := s.receiptCount(index)
	response, _ := s.call(method, path, body, token, want)
	if s.receiptCount(index) != count || response.Header.Get("X-Service") != "" {
		s.t.Fatalf("%s %s reached the service", method, path)
	}
}
