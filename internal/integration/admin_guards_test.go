// Sign-in throttling and browser request guards.

package integration

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
)

// Repeated failures lock one administrator name, a burst of
// failures stops every attempt, and concurrent logins stay isolated.
func TestLoginThrottling(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	_, secondPassword := addAdmin(e, gatewaytest.Binaries.Plain, "second", "read")

	var wg sync.WaitGroup
	sessions := make(chan gatewaytest.AdminSession, 8)
	statuses := make(chan int, 8)
	for range 8 {
		wg.Go(func() {
			s, code := e.Login("second", secondPassword)
			statuses <- code
			if code == http.StatusCreated {
				sessions <- s
			}
		})
	}
	wg.Wait()
	close(sessions)
	close(statuses)
	for code := range statuses {
		if code != http.StatusCreated && code != http.StatusServiceUnavailable {
			t.Fatalf("concurrent login: %d", code)
		}
	}
	seen := map[string]bool{}
	for s := range sessions {
		if seen[s.Cookie] {
			t.Fatal("two concurrent logins share a session")
		}
		seen[s.Cookie] = true
		if code, body, _ := e.As(s, http.MethodGet, "/admin/session", ""); code != http.StatusOK || !strings.Contains(body, s.CSRF) {
			t.Fatalf("concurrent session: %d", code)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no concurrent login succeeded")
	}

	for range gatewaytest.NameLimit {
		if _, code := e.Login(gatewaytest.HarnessAdmin, "wrong-password-guess"); code != http.StatusUnauthorized {
			t.Fatalf("failed login: %d", code)
		}
	}
	if _, code := e.Login(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword); code != http.StatusTooManyRequests {
		t.Fatalf("correct password on a locked name: %d", code)
	}
	if _, code := e.Login("second", secondPassword); code != http.StatusCreated {
		t.Fatalf("another name while one is locked: %d", code)
	}

	for i := gatewaytest.NameLimit; i < gatewaytest.WindowLimit; i++ {
		if _, code := e.Login(fmt.Sprintf("guess-%d", i), "wrong-password-guess"); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, code)
		}
	}
	if _, code := e.Login("second", secondPassword); code != http.StatusTooManyRequests {
		t.Fatalf("login after %d failures in the window: %d", gatewaytest.WindowLimit, code)
	}
	recorded := func(events []map[string]any) map[string]bool {
		reasons := map[string]bool{}
		for _, ev := range events {
			if ev["kind"] == "admin.rejected" {
				reasons[ev["reason"].(string)] = true
			}
		}
		return reasons
	}
	complete := func(reasons map[string]bool) bool {
		return reasons["locked"] && reasons["throttled"] && reasons["bad_credentials"]
	}
	reasons := recorded(e.EventsWhen(func(events []map[string]any) bool { return complete(recorded(events)) }))
	if !complete(reasons) {
		t.Fatalf("refusal reasons recorded: %v", reasons)
	}
	assertAbsent(t, e, "wrong-password-guess", secondPassword)
}

// State-changing requests need the admin origin and the
// session's CSRF token, every request needs the admin host, and no header
// can claim an identity or permission.
func TestBrowserRequestGuards(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	reader, _ := addAdmin(e, gatewaytest.Binaries.Plain, "reader", "read")
	writer := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	other := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	before := e.Status()

	put := `{"reason":"test containment"}`
	cookie := []string{"Cookie", gatewaytest.AdminCookie + "=" + writer.Cookie}
	origin := []string{"Origin", e.AdminOrigin()}
	csrf := []string{gatewaytest.AdminCSRF, writer.CSRF}
	cases := []struct {
		name   string
		header []string
	}{
		{"no origin", slices.Concat(cookie, csrf)},
		{"another site", slices.Concat(cookie, csrf, []string{"Origin", "https://evil.example"})},
		{"opaque origin", slices.Concat(cookie, csrf, []string{"Origin", "null"})},
		{"same host, another port", slices.Concat(cookie, csrf, []string{"Origin", "http://127.0.0.1:1"})},
		{"same port, another host name", slices.Concat(cookie, csrf, []string{"Origin", "http://localhost:" + gatewaytest.Port(e.Admin)})},
		{"no CSRF token", slices.Concat(cookie, origin)},
		{"wrong CSRF token", slices.Concat(cookie, origin, []string{gatewaytest.AdminCSRF, session.NewToken()})},
		{"another session's CSRF token", slices.Concat(cookie, origin, []string{gatewaytest.AdminCSRF, other.CSRF})},
	}
	for i, tc := range cases {
		header := append(tc.header, "If-Match", `"r1"`, "Idempotency-Key", fmt.Sprintf("browser-guard-%04d", i))
		if code, body, _ := e.AdminSend(http.MethodPut, "/admin/blocked-accounts/mallory", put, header...); code != http.StatusForbidden {
			t.Errorf("%s: %d %s", tc.name, code, body)
		}
	}
	for _, host := range []string{"localhost:" + gatewaytest.Port(e.Admin), "evil.example", "127.0.0.1"} {
		header := append(writer.Headers(e), "Host", host)
		if code, _, _ := e.AdminSend(http.MethodGet, "/admin/status", "", header...); code != http.StatusBadRequest {
			t.Errorf("Host %s: %d", host, code)
		}
	}
	login := string(gatewaytest.MustJSON(map[string]string{"name": gatewaytest.HarnessAdmin, "password": gatewaytest.HarnessPassword}))
	for _, header := range [][]string{nil, {"Origin", "https://evil.example"}} {
		if code, _, _ := e.AdminSend(http.MethodPost, "/admin/session", login, header...); code != http.StatusForbidden {
			t.Errorf("login with origin %v: %d", header, code)
		}
	}
	code, _, header := e.AdminSend(http.MethodOptions, "/admin/status", "", "Origin", "https://evil.example", "Access-Control-Request-Method", "GET")
	if code != http.StatusMethodNotAllowed {
		t.Errorf("preflight: %d", code)
	}
	for name := range header {
		if strings.HasPrefix(name, "Access-Control-") {
			t.Errorf("CORS header %s sent", name)
		}
	}

	// Identity and permission claims in headers grant nothing.
	forged := []string{"X-Forwarded-For", "127.0.0.1", "X-Actor", gatewaytest.HarnessAdmin, "X-Admin", "true", "X-Role", "manage_subjects",
		"X-Permissions", "manage_subjects", "X-Gateway-Subject", gatewaytest.HarnessAdmin, "Forwarded", "for=127.0.0.1"}
	if code, _, _ := e.AdminSend(http.MethodGet, "/admin/status", "", forged...); code != http.StatusUnauthorized {
		t.Errorf("anonymous request with forged identity headers: %d", code)
	}
	readerHeader := append(append(reader.Headers(e), forged...), "If-Match", `"r1"`, "Idempotency-Key", "browser-guard-reader")
	if code, _, _ := e.AdminSend(http.MethodPut, "/admin/blocked-accounts/mallory", put, readerHeader...); code != http.StatusForbidden {
		t.Errorf("reader with forged permission headers: %d", code)
	}
	events := e.EventsWhen(func(events []map[string]any) bool {
		return gatewaytest.CountKind(events, "admin.denied") >= len(cases)+1
	})
	denied := 0
	for _, ev := range events {
		if ev["kind"] == "admin.denied" && ev["reason"] == "permission" {
			denied++
			if ev["actor"] != "reader" {
				t.Errorf("denial attributed to %v", ev["actor"])
			}
		}
	}
	if denied != 1 {
		t.Errorf("%d permission denials recorded, want 1", denied)
	}

	if after := e.Status(); after.Generation != before.Generation || after.Revision != 1 {
		t.Fatalf("refused requests changed the state: %+v", after)
	}
	if code, body, _ := e.HarnessCall(http.MethodGet, "/admin/history", ""); code != http.StatusOK || strings.Contains(body, "membership") {
		t.Fatalf("history after refused requests: %d %s", code, body)
	}
}
