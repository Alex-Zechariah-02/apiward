// Admin API client: sign-in and sessions, requests with the CSRF and Origin
// checks satisfied, the harness administrator, status and health reads, and
// the operator commands run against a deployment.

package gatewaytest

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
)

// AdminSession is an administrator's session cookie value and CSRF token.
type AdminSession struct {
	Cookie, CSRF string
}

// Headers are what a session request carries: the cookie, the CSRF token and
// the admin origin.
func (s AdminSession) Headers(e *Env) []string {
	return []string{"Cookie", AdminCookie + "=" + s.Cookie, AdminCSRF, s.CSRF, "Origin", e.AdminOrigin()}
}

// AdminOrigin is the Origin a browser on the admin listener sends.
func (e *Env) AdminOrigin() string { return "http://" + e.Admin }

// AdminSend sends one request to the admin listener exactly as given: a
// non-empty body is sent as JSON, and header holds name/value pairs. A
// transport failure, such as a gateway that exited, returns status 0.
func (e *Env) AdminSend(method, path, body string, header ...string) (int, string, http.Header) {
	e.T.Helper()
	req, err := http.NewRequest(method, "http://"+e.Admin+path, strings.NewReader(body))
	if err != nil {
		e.T.Fatal(err)
	}
	if body == "" {
		req.Body = http.NoBody
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(header); i += 2 {
		if header[i] == "Host" {
			req.Host = header[i+1]
			continue
		}
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, err.Error(), nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), resp.Header
}

// Login starts a session and returns it with the response status.
func (e *Env) Login(name, password string) (AdminSession, int) {
	e.T.Helper()
	body := string(MustJSON(map[string]string{"name": name, "password": password}))
	code, data, header := e.AdminSend(http.MethodPost, "/admin/session", body, "Origin", e.AdminOrigin())
	if code != http.StatusCreated {
		return AdminSession{}, code
	}
	var view struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal([]byte(data), &view)
	for _, cookie := range (&http.Response{Header: header}).Cookies() {
		if cookie.Name == AdminCookie {
			return AdminSession{Cookie: cookie.Value, CSRF: view.CSRF}, code
		}
	}
	e.T.Fatalf("login answered 201 without a session cookie: %v", header)
	return AdminSession{}, 0
}

// HarnessCall sends a request as the harness administrator, logging in when
// there is no session and once more if the session has ended (a restart ends
// every session). Authentication is checked before anything else, so a
// request refused with 401 was never processed and is safe to resend.
func (e *Env) HarnessCall(method, path, body string, header ...string) (int, string, http.Header) {
	e.T.Helper()
	for range 2 {
		session, code := e.harnessSession()
		if code != http.StatusCreated {
			return code, "harness login failed", nil
		}
		code, data, h := e.AdminSend(method, path, body, append(session.Headers(e), header...)...)
		if code != http.StatusUnauthorized {
			return code, data, h
		}
		e.forgetSession(session)
	}
	return http.StatusUnauthorized, "harness session refused", nil
}

// harnessSession returns the harness administrator's session, logging in
// once when there is none; concurrent callers share that one login. The
// status is the login's, or 201 for a session already held.
func (e *Env) harnessSession() (AdminSession, int) {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	if e.session.Cookie == "" {
		session, code := e.Login(HarnessAdmin, HarnessPassword)
		if code != http.StatusCreated {
			return AdminSession{}, code
		}
		e.session = session
	}
	return e.session, http.StatusCreated
}

// forgetSession drops a refused session, unless another caller has already
// replaced it with a new one.
func (e *Env) forgetSession(refused AdminSession) {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	if e.session.Cookie == refused.Cookie {
		e.session = AdminSession{}
	}
}

// Publish sends a whole policy through the test publication hook, which
// exists only in the fault-injection build.
func (e *Env) Publish(change controller.Change) (controller.Outcome, int) {
	e.T.Helper()
	code, body, _ := e.HarnessCall(http.MethodPost, "/test/publish", string(MustJSON(change)))
	var outcome controller.Outcome
	json.Unmarshal([]byte(body), &outcome)
	return outcome, code
}

// AdminRaw sends a body exactly as given, as the harness administrator.
func (e *Env) AdminRaw(method, path, body string) (int, string) {
	e.T.Helper()
	code, data, _ := e.HarnessCall(method, path, body)
	return code, data
}

// Status is the Admin API status read: the state, admission and the revisions
// and deadline in force.
type Status struct {
	State       string    `json:"state"`
	Admission   string    `json:"admission"`
	AuditFailed bool      `json:"audit_failed"`
	Revision    int64     `json:"revision"`
	Generation  string    `json:"generation"`
	JWTKey      string    `json:"jwt_key_sha256"`
	Confirmed   int64     `json:"confirmed"`
	Provisional int64     `json:"provisional"`
	Deadline    time.Time `json:"deadline"`
	NotAfter    time.Time `json:"not_after"`
	Overrides   []int64   `json:"overrides"`
}

// Status reads the status as the harness administrator; any answer but 200
// fails the test.
func (e *Env) Status() Status {
	e.T.Helper()
	code, body, _ := e.HarnessCall(http.MethodGet, "/admin/status", "")
	if code != http.StatusOK {
		e.T.Fatalf("status: %d %s", code, body)
	}
	var s Status
	json.Unmarshal([]byte(body), &s)
	return s
}

// Health reads the unauthenticated health state.
func (e *Env) Health() string {
	e.T.Helper()
	code, body, _ := e.AdminSend(http.MethodGet, "/admin/health", "")
	var h struct {
		State string `json:"state"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &h) != nil {
		e.T.Fatalf("health: %d %s", code, body)
	}
	return h.State
}

// UnavailableReason returns the reason of the last controller.unavailable
// event, for states in which no administrator can log in to read the status.
func (e *Env) UnavailableReason() string {
	e.T.Helper()
	events := e.EventsWhen(func(events []map[string]any) bool { return CountKind(events, "controller.unavailable") > 0 })
	reason := ""
	for _, ev := range events {
		if ev["kind"] == "controller.unavailable" {
			reason, _ = ev["reason"].(string)
		}
	}
	return reason
}

// RunOperator runs a local operator command of the gateway binary against this
// environment's configuration. It returns the combined output, which holds
// any enrolment secret and any refusal message, and the exit code.
func (e *Env) RunOperator(binary string, extraEnv []string, command string, args ...string) (string, int) {
	e.T.Helper()
	cmd := exec.Command(binary, append([]string{command, "--config", e.Config}, args...)...)
	cmd.Env = append(os.Environ(), "GATEWAY_FAULT=")
	cmd.Env = append(cmd.Env, extraEnv...)
	output, err := cmd.CombinedOutput()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		e.T.Fatalf("running %s: %v", command, err)
	}
	e.T.Logf("%s %s --config %s %v: exit %d", filepath.Base(binary), command, e.Config, args, code)
	return string(output), code
}

// EnrolmentSecret extracts the secret from an install or enrol command's
// output line "enrolment secret for <name>...: <secret>".
func EnrolmentSecret(t *testing.T, output string) string {
	t.Helper()
	for line := range strings.Lines(output) {
		if strings.HasPrefix(line, "enrolment secret for ") {
			index := strings.LastIndex(line, ": ")
			return strings.TrimSpace(line[index+2:])
		}
	}
	t.Fatalf("no enrolment secret in output %q", output)
	return ""
}

// MustLogin is Login that fails the test unless a session is created.
func (e *Env) MustLogin(name, password string) AdminSession {
	e.T.Helper()
	session, code := e.Login(name, password)
	if code != http.StatusCreated {
		e.T.Fatalf("login as %s: %d", name, code)
	}
	return session
}

// As sends a request with an administrator's session, origin and CSRF token.
func (e *Env) As(s AdminSession, method, path, body string, header ...string) (int, string, http.Header) {
	e.T.Helper()
	return e.AdminSend(method, path, body, append(s.Headers(e), header...)...)
}
