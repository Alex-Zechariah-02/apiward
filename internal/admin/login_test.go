// Sign-in and enrolment: the sign-in record, failures of the gateway's own
// parts, enrolment throttling and the password rule.

package admin

import (
	"bufio"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/monitor"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

const testOrigin = "http://127.0.0.1:1"

// withPassword opens a controller whose administrator alice has password.
func withPassword(t *testing.T, password string) *controller.Controller {
	t.Helper()
	return openSeeded(t, storetest.Options{Administrator: "alice"}, func(database string) {
		db, err := sql.Open("sqlite", store.DatabaseURI(database))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec("UPDATE administrator SET password = ? WHERE name = 'alice'", hashPassword(password)); err != nil {
			t.Fatal(err)
		}
	})
}

// post sends body to handler as a same-origin JSON request.
func post(handler http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

// failures reads gateway_admin_failures_total for reason from the metrics.
func failures(t *testing.T, c *controller.Controller, reason string) string {
	t.Helper()
	w := httptest.NewRecorder()
	monitor.Metrics(c.Observations(), func() []monitor.Gauge { return nil }).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	prefix := "gateway_admin_failures_total{reason=\"" + reason + "\"} "
	for lines := bufio.NewScanner(w.Body); lines.Scan(); {
		if value, found := strings.CutPrefix(lines.Text(), prefix); found {
			return value
		}
	}
	t.Fatalf("no %s line in the metrics", prefix)
	return ""
}

func TestSignIn(t *testing.T) {
	const password = "a long and unusual test password"
	login := `{"name":"alice","password":"` + password + `"}`

	// The client gets its session only after the sign-in record is durable.
	t.Run("record before session", func(t *testing.T) {
		c := withPassword(t, password)
		s := testServer(c)
		if w := post(s.handleLogin, "/admin/session", login); w.Code != http.StatusCreated || len(w.Result().Cookies()) != 1 {
			t.Fatalf("sign-in: %d %s", w.Code, w.Body)
		}
		c.Audit().Fail(errors.New("test: the security log failed"))
		w := post(s.handleLogin, "/admin/session", login)
		if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 || c.Sessions().Count(time.Now()) != 1 {
			t.Fatalf("sign-in with a failed log: %d %v, %d sessions", w.Code, w.Result().Cookies(), c.Sessions().Count(time.Now()))
		}
		if got := failures(t, c, "audit"); got != "1" {
			t.Fatalf("audit failures counted: %s", got)
		}
	})

	// A sign-in shed for lack of a hashing slot is answered busy and counted.
	t.Run("busy is counted", func(t *testing.T) {
		c := withPassword(t, password)
		s := testServer(c)
		for range maxHashing {
			s.hashing <- struct{}{}
		}
		if w := post(s.handleLogin, "/admin/session", login); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "busy") {
			t.Fatalf("sign-in without a slot: %d %s", w.Code, w.Body)
		}
		if got := failures(t, c, "busy"); got != "1" {
			t.Fatalf("busy failures counted: %s", got)
		}
	})

	// Wrong enrolment secrets count against the name like wrong passwords.
	t.Run("enrolment failures lock the name", func(t *testing.T) {
		s := testServer(openController(t))
		enrol := `{"name":"bob","secret":"not-the-secret","password":"` + password + `"}`
		for range maxNameFailures {
			if w := post(s.handleEnrol, "/admin/enrol", enrol); w.Code != http.StatusUnauthorized {
				t.Fatalf("wrong secret: %d %s", w.Code, w.Body)
			}
		}
		if w := post(s.handleEnrol, "/admin/enrol", enrol); w.Code != http.StatusTooManyRequests {
			t.Fatalf("after %d wrong secrets: %d %s", maxNameFailures, w.Code, w.Body)
		}
	})

	// The password rule refuses a common password in any letter case.
	t.Run("common passwords", func(t *testing.T) {
		for candidate, want := range map[string]bool{
			"qwerty123456789": false,
			"QWERTY123456789": false,
			password:          true,
			"short":           false,
		} {
			if got := validPassword(candidate); got != want {
				t.Errorf("validPassword(%q) = %v, want %v", candidate, got, want)
			}
		}
	})
}
