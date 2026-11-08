// Admin sessions, API client tokens and secret-safe session events.

package integration

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/session"
)

// Sessions are server-side, unpredictable,
// bounded in time and never adopted from the client.
func TestAdminSessions(t *testing.T) {
	t.Run("issued session", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		login := string(gatewaytest.MustJSON(map[string]string{"name": gatewaytest.HarnessAdmin, "password": gatewaytest.HarnessPassword}))
		code, body, header := e.AdminSend(http.MethodPost, "/admin/session", login, "Origin", e.AdminOrigin())
		if code != http.StatusCreated {
			t.Fatalf("login: %d %s", code, body)
		}
		setCookie := header.Values("Set-Cookie")
		if len(setCookie) != 1 {
			t.Fatalf("Set-Cookie %v", setCookie)
		}
		for _, attribute := range []string{gatewaytest.AdminCookie + "=", "; Path=/", "; HttpOnly", "; Secure", "; SameSite=Strict"} {
			if !strings.Contains(setCookie[0], attribute) {
				t.Errorf("cookie lacks %q", attribute)
			}
		}
		if strings.Contains(strings.ToLower(setCookie[0]), "domain=") {
			t.Error("cookie names a domain")
		}
		cookie := (&http.Response{Header: header}).Cookies()[0].Value
		raw, err := base64.RawURLEncoding.DecodeString(cookie)
		if err != nil || len(raw) != 32 {
			t.Fatalf("session token is not 32 random bytes: %d %v", len(raw), err)
		}
		view := fromJSON[map[string]any](t, body)
		if view["name"] != gatewaytest.HarnessAdmin || view["csrf_token"] == cookie || len(view["csrf_token"].(string)) != 43 {
			t.Fatalf("session view %v", view)
		}
		if strings.Contains(body, "argon2") || strings.Contains(body, gatewaytest.HarnessPassword) {
			t.Fatal("session view discloses the credential")
		}
		again := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		if again.Cookie == cookie || again.CSRF == view["csrf_token"] {
			t.Fatal("a second login reused the token")
		}
	})

	t.Run("wrong credentials", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		var bodies []string
		for _, credentials := range []map[string]string{
			{"name": gatewaytest.HarnessAdmin, "password": "not-the-password-at-all"},
			{"name": "nobody", "password": gatewaytest.HarnessPassword},
		} {
			code, body, header := e.AdminSend(http.MethodPost, "/admin/session", string(gatewaytest.MustJSON(credentials)), "Origin", e.AdminOrigin())
			if code != http.StatusUnauthorized || header.Get("Set-Cookie") != "" {
				t.Fatalf("login %v: %d", credentials["name"], code)
			}
			bodies = append(bodies, body)
		}
		if bodies[0] != bodies[1] || strings.TrimSpace(bodies[0]) != `{"error":"unauthenticated"}` {
			t.Fatalf("refusals differ or disclose detail: %q %q", bodies[0], bodies[1])
		}
		if code, _, _ := e.AdminSend(http.MethodPost, "/admin/session", `{"name":"harness"}`, "Origin", e.AdminOrigin()); code != http.StatusUnauthorized {
			t.Fatalf("login without password: %d", code)
		}
		if code, _, _ := e.AdminSend(http.MethodPost, "/admin/session", `{"name":`, "Origin", e.AdminOrigin()); code != http.StatusBadRequest {
			t.Fatalf("malformed login: %d", code)
		}
		events := e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "admin.rejected") >= 3 })
		for _, ev := range events {
			if ev["kind"] == "admin.rejected" && (ev["actor"] != nil || ev["reason"] != "bad_credentials") {
				t.Fatalf("refusal event %v", ev)
			}
		}
		assertAbsent(t, e, "not-the-password-at-all", gatewaytest.HarnessPassword)
	})

	t.Run("forged and tampered tokens", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		valid := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		tampered := []byte(valid.Cookie)
		tampered[len(tampered)-1] ^= 1
		for _, token := range []string{"", "x", strings.Repeat("A", 43), string(tampered), valid.Cookie + "A", session.NewToken(), valid.CSRF} {
			code, body, _ := e.AdminSend(http.MethodGet, "/admin/status", "", "Cookie", gatewaytest.AdminCookie+"="+token)
			if code != http.StatusUnauthorized || strings.Contains(body, "revision") {
				t.Fatalf("token %q: %d %s", token, code, body)
			}
		}
		// A token chosen by the client is never adopted at login.
		chosen := session.NewToken()
		code, _, header := e.AdminSend(http.MethodPost, "/admin/session",
			string(gatewaytest.MustJSON(map[string]string{"name": gatewaytest.HarnessAdmin, "password": gatewaytest.HarnessPassword})),
			"Origin", e.AdminOrigin(), "Cookie", gatewaytest.AdminCookie+"="+chosen)
		if code != http.StatusCreated || strings.Contains(header.Get("Set-Cookie"), chosen) {
			t.Fatalf("login with a chosen token: %d", code)
		}
		if code, _, _ := e.AdminSend(http.MethodGet, "/admin/status", "", "Cookie", gatewaytest.AdminCookie+"="+chosen); code != http.StatusUnauthorized {
			t.Fatalf("chosen token after login: %d", code)
		}
	})

	t.Run("logout and expiry", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.WriteConfig(gatewaytest.ConfigOptions{Admin: map[string]any{"admin_idle_timeout": "1s", "admin_session_lifetime": "4s"}})
		e.Start(gatewaytest.Binaries.Plain)

		ended := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		if code, _, _ := e.As(ended, http.MethodDelete, "/admin/session", ""); code != http.StatusNoContent {
			t.Fatalf("logout: %d", code)
		}
		if code, _, _ := e.As(ended, http.MethodGet, "/admin/session", ""); code != http.StatusUnauthorized {
			t.Fatalf("session after logout: %d", code)
		}

		idle := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		time.Sleep(1500 * time.Millisecond)
		if code, _, _ := e.As(idle, http.MethodGet, "/admin/session", ""); code != http.StatusUnauthorized {
			t.Fatalf("session after the idle timeout: %d", code)
		}

		active := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		started := time.Now()
		for {
			time.Sleep(400 * time.Millisecond)
			code, _, _ := e.As(active, http.MethodGet, "/admin/session", "")
			elapsed := time.Since(started)
			if code == http.StatusOK && elapsed < 4*time.Second {
				continue
			}
			if code != http.StatusUnauthorized || elapsed < 3800*time.Millisecond {
				t.Fatalf("after %s of activity: %d", elapsed, code)
			}
			break
		}
	})

	t.Run("restart ends sessions", func(t *testing.T) {
		e := gatewaytest.NewEnv(t)
		gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
		e.Start(gatewaytest.Binaries.Plain)
		before := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
		e.Start(gatewaytest.Binaries.Plain)
		if code, _, _ := e.As(before, http.MethodGet, "/admin/session", ""); code != http.StatusUnauthorized {
			t.Fatalf("session after restart: %d", code)
		}
		e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	})

	t.Run("listener and settings", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			setup func(e *gatewaytest.Env)
			cause string
		}{
			{"wildcard listener", func(e *gatewaytest.Env) { e.Admin = "0.0.0.0:" + gatewaytest.Port(e.Admin) }, "loopback"},
			{"host name listener", func(e *gatewaytest.Env) { e.Admin = "localhost:" + gatewaytest.Port(e.Admin) }, "loopback"},
			{"idle timeout too short", func(e *gatewaytest.Env) {}, "admin_idle_timeout"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := gatewaytest.NewEnv(t)
				gatewaytest.Seed(t, e.Database, e.Policy(e.A, false), gatewaytest.SeedOptions{})
				tc.setup(e)
				options := gatewaytest.ConfigOptions{}
				if tc.cause == "admin_idle_timeout" {
					options.Admin = map[string]any{"admin_idle_timeout": "500ms"}
				}
				e.WriteConfig(options)
				e.Run(gatewaytest.Binaries.Plain)
				if code := e.WaitExit(); code == 0 || !strings.Contains(e.Output.String(), tc.cause) {
					t.Fatalf("exit %d\n%s", code, e.Output)
				}
			})
		}
	})
}

// A valid API-client token is never an administrator credential,
// even when its subject has an administrator's name.
func TestAPIClientTokenIsNotAdminCredential(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	token := gatewaytest.Issuer.TokenFor(t, gatewaytest.HarnessAdmin)
	put := `{"reason":"test containment"}`
	for _, header := range [][]string{
		{"Authorization", "Bearer " + token},
		{"Cookie", gatewaytest.AdminCookie + "=" + token},
		{"Authorization", "Bearer " + gatewaytest.Issuer.TokenFor(t, "alice")},
	} {
		if code, _, _ := e.AdminSend(http.MethodGet, "/admin/status", "", header...); code != http.StatusUnauthorized {
			t.Errorf("status with %s: %d", header[0], code)
		}
		mutation := append([]string{"Origin", e.AdminOrigin(), "If-Match", `"r1"`, "Idempotency-Key", "api-token-probe-01"}, header...)
		if code, _, _ := e.AdminSend(http.MethodPut, "/admin/blocked-accounts/mallory", put, mutation...); code != http.StatusUnauthorized {
			t.Errorf("membership change with %s: %d", header[0], code)
		}
	}
	if s := e.Status(); s.Revision != 1 {
		t.Fatalf("revision %d after the probes", s.Revision)
	}
	// The same token is still an ordinary API credential on the data plane.
	if code, _ := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice")); code != http.StatusOK {
		t.Fatalf("data plane request with a valid token: %d", code)
	}
}

// The administrative events of a whole
// session carry the trusted actor and never a secret.
func TestAdminEventsAreSecretSafe(t *testing.T) {
	e, secret := installEnv(t, gatewaytest.Binaries.Plain)
	password := testPassword()
	if code, _ := enrol(e, "root", secret, password); code != http.StatusCreated {
		t.Fatal("enrolment failed")
	}
	root := e.MustLogin("root", password)
	e.Login("root", "a-wrong-password-value")
	code, body, _ := e.As(root, http.MethodPost, "/admin/candidates", string(gatewaytest.MustJSON(map[string]any{"policy": denyAllPolicy(e)})),
		"If-Match", `"r0"`, "Idempotency-Key", "secret-safe-candidate")
	if code != http.StatusCreated {
		t.Fatalf("staging: %d %s", code, body)
	}
	changed := testPassword()
	e.As(root, http.MethodPut, "/admin/password", string(gatewaytest.MustJSON(map[string]string{"current_password": password, "new_password": changed})))
	root = e.MustLogin("root", changed)
	e.As(root, http.MethodDelete, "/admin/session", "")

	recorded := []string{"admin.authenticated", "admin.rejected", "admin.logout", "transition.intent", "transition.committed"}
	events := e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.HasKinds(events, recorded...) })
	for _, ev := range events {
		kind := ev["kind"].(string)
		if (strings.HasPrefix(kind, "admin.") && kind != "admin.rejected") || strings.HasPrefix(kind, "transition.") {
			if ev["actor"] != "root" && ev["actor"] != "operator" {
				t.Errorf("event %s attributed to %v", kind, ev["actor"])
			}
		}
	}
	for _, kind := range recorded {
		if gatewaytest.CountKind(events, kind) == 0 {
			t.Errorf("no %s event", kind)
		}
	}
	assertAbsent(t, e, secret, password, changed, "a-wrong-password-value", root.Cookie, root.CSRF)
}
