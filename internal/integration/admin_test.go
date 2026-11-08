// Admin API helpers and one-time local bootstrap.

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// testPassword returns a fresh administrator password for one test.
func testPassword() string { return "pw-" + session.NewToken() }

// installEnv creates a fresh installation with the operator install command,
// for a first administrator named root, and starts the gateway on it. It
// returns the enrolment secret the command printed.
func installEnv(t *testing.T, binary string) (*gatewaytest.Env, string) {
	t.Helper()
	e := gatewaytest.NewEnv(t)
	out, code := e.RunOperator(binary, nil, "install", "--admin", "root")
	if code != 0 {
		t.Fatalf("install exited %d: %s", code, out)
	}
	secret := gatewaytest.EnrolmentSecret(t, out)
	e.Start(binary)
	return e, secret
}

// enrol consumes an enrolment secret over the Admin API.
func enrol(e *gatewaytest.Env, name, secret, password string) (int, string) {
	e.T.Helper()
	body := string(gatewaytest.MustJSON(map[string]string{"name": name, "secret": secret, "password": password}))
	code, data, _ := e.AdminSend(http.MethodPost, "/admin/enrol", body, "Origin", e.AdminOrigin())
	return code, data
}

// addAdmin enrols another administrator through the operator command (with
// the gateway stopped) and the Admin API, and logs it in.
func addAdmin(e *gatewaytest.Env, binary, name, permissions string) (gatewaytest.AdminSession, string) {
	e.T.Helper()
	e.Stop()
	out, code := e.RunOperator(binary, nil, "enrol", "--admin", name, "--permissions", permissions)
	if code != 0 {
		e.T.Fatalf("enrol %s exited %d: %s", name, code, out)
	}
	e.Start(binary)
	password := testPassword()
	if code, body := enrol(e, name, gatewaytest.EnrolmentSecret(e.T, out), password); code != http.StatusCreated {
		e.T.Fatalf("enrolling %s: %d %s", name, code, body)
	}
	return e.MustLogin(name, password), password
}

// assertAbsent fails if any value appears in the audit files, the gateway's
// output or the database files.
func assertAbsent(t *testing.T, e *gatewaytest.Env, values ...string) {
	t.Helper()
	files, _ := filepath.Glob(e.AuditLog + "*")
	databaseFiles, _ := filepath.Glob(e.Database + "*")
	files = append(files, databaseFiles...)
	sources := map[string]string{"gateway output": e.Output.String()}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err == nil {
			sources[filepath.Base(file)] = string(data)
		}
	}
	for name, content := range sources {
		for _, value := range values {
			if value != "" && strings.Contains(content, value) {
				t.Errorf("%s contains a secret value", name)
			}
		}
	}
}

// denyAllPolicy is the standard test catalogue with every operation denied
// and no roles, permits or subjects: a valid first or recovery base.
func denyAllPolicy(e *gatewaytest.Env) policy.Policy {
	p := e.Policy(e.A, true)
	for i := range p.Operations {
		p.Operations[i].Access = "deny"
	}
	return p
}

func fromJSON[T any](t *testing.T, body string) T {
	t.Helper()
	var value T
	if err := json.Unmarshal([]byte(body), &value); err != nil {
		t.Fatalf("decoding %q: %v", body, err)
	}
	return value
}

// The first administrator can only be created with the
// one-time secret of the local install command, exactly once.
func TestBootstrapIsLocalAndOneTime(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "install", "--admin", "root")
	if code != 0 {
		t.Fatalf("install exited %d: %s", code, out)
	}
	secret := gatewaytest.EnrolmentSecret(t, out)

	if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM administrator`); n != 0 {
		t.Fatalf("%d administrators exist before enrolment", n)
	}
	if got := gatewaytest.QueryString(t, e.Database, `SELECT secret FROM enrolment WHERE administrator = 'root'`); got != session.Hash(secret) {
		t.Fatal("the stored enrolment is not the hash of the printed secret")
	}
	if mode := gatewaytest.QueryString(t, e.Database, `SELECT mode FROM deployment`); mode != store.ModeBootstrap {
		t.Fatalf("installed mode %q", mode)
	}

	// A second install never replaces the database.
	before := gatewaytest.FileSHA256(t, e.Database)
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "install", "--admin", "other"); code == 0 {
		t.Fatalf("second install succeeded: %s", out)
	}
	if gatewaytest.FileSHA256(t, e.Database) != before {
		t.Fatal("second install changed the database")
	}

	e.Start(gatewaytest.Binaries.Plain)
	if health := e.Health(); health != store.ModeBootstrap {
		t.Fatalf("health %q", health)
	}
	for _, path := range []string{"/a/x", "/d", "/admin/status"} {
		if code, _ := e.Get(path); code != http.StatusServiceUnavailable {
			t.Fatalf("data plane %s before genesis: %d", path, code)
		}
	}

	// Without the secret, nothing creates or authenticates an administrator.
	password := testPassword()
	attempts := []struct{ name, secret string }{
		{"root", ""}, {"root", "wrong"}, {"root", session.NewToken()}, {"other", secret}, {"admin", secret},
	}
	for _, a := range attempts {
		if code, body := enrol(e, a.name, a.secret, password); code != http.StatusUnauthorized {
			t.Errorf("enrol %s with secret %q: %d %s", a.name, a.secret, code, body)
		}
	}
	for _, name := range []string{"root", "admin", "harness"} {
		if _, code := e.Login(name, password); code != http.StatusUnauthorized {
			t.Errorf("login as %s before enrolment: %d", name, code)
		}
	}
	for _, path := range []string{"/admin/status", "/admin/policy", "/admin/history", "/admin/candidates"} {
		if code, _, _ := e.AdminSend(http.MethodGet, path, ""); code != http.StatusUnauthorized {
			t.Errorf("GET %s without a session: %d", path, code)
		}
	}
	// A password below the minimum is refused without consuming the secret.
	if code, _ := enrol(e, "root", secret, "short-password"); code != http.StatusBadRequest {
		t.Fatalf("short password: %d", code)
	}

	// The secret establishes exactly one administrator.
	code, body := enrol(e, "root", secret, password)
	if code != http.StatusCreated || !strings.Contains(body, `"manage_policy"`) || !strings.Contains(body, `"read_history"`) {
		t.Fatalf("enrolment: %d %s", code, body)
	}
	session := e.MustLogin("root", password)
	if code, _, _ := e.As(session, http.MethodGet, "/admin/status", ""); code != http.StatusOK {
		t.Fatalf("status as root: %d", code)
	}

	// The consumed secret cannot be replayed, for the same or another name.
	for _, name := range []string{"root", "other"} {
		if code, _ := enrol(e, name, secret, testPassword()); code != http.StatusUnauthorized {
			t.Errorf("replayed secret for %s: %d", name, code)
		}
	}
	if _, code := e.Login("root", password); code != http.StatusCreated {
		t.Fatal("the replay attempts changed the credential")
	}

	e.Stop()
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM administrator`); n != 1 {
		t.Fatalf("%d administrators, want 1", n)
	}
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT credential FROM administrator WHERE name = 'root'`); n != 1 {
		t.Fatalf("credential version %d, want 1 (never overwritten)", n)
	}
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM enrolment`); n != 0 {
		t.Fatalf("%d enrolments remain", n)
	}
	hash := gatewaytest.QueryString(t, e.Database, `SELECT password FROM administrator WHERE name = 'root'`)
	if !strings.HasPrefix(hash, gatewaytest.PasswordPrefix) {
		t.Fatalf("stored credential is not an argon2id hash with the configured parameters: %.20s", hash)
	}
	assertAbsent(t, e, secret, password)
}
