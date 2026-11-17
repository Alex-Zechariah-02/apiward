// Admin API records: read-only POST requests, database failures and the
// lifetime of state-changing requests.

package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/controller"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

// A POST that only asks a question is recorded as a read, and a request the
// database cannot serve is recorded and counted.
func TestAdminRecords(t *testing.T) {
	c := openSeeded(t, storetest.Options{Administrator: "alice"}, nil)
	s := testServer(c)
	handler := s.Handler()
	token, created, err := c.Sessions().Create("alice", 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	send := func(ctx context.Context, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
		r.Host = "127.0.0.1:1"
		r.Header.Set("Origin", testOrigin)
		r.Header.Set("X-CSRF-Token", created.CSRF)
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	send(t.Context(), http.MethodPost, "/admin/access-check", `{}`)
	// An expired deadline makes the store read fail without touching the
	// database.
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	if w := send(expired, http.MethodGet, "/admin/status", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status with a failed store read: %d %s", w.Code, w.Body)
	}
	if got := failures(t, c, "store"); got != "1" {
		t.Fatalf("store failures counted: %s", got)
	}
	// A client that left is not a gateway failure: nothing more is counted.
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	send(cancelled, http.MethodGet, "/admin/status", "")
	if got := failures(t, c, "store"); got != "1" {
		t.Fatalf("a request whose client left was counted as a store failure: %s", got)
	}
	// A signed-in read the database cannot serve names its administrator.
	who := caller{admin: store.Administrator{Name: "alice"}, session: created}
	s.handlePolicy(httptest.NewRecorder(), httptest.NewRequestWithContext(expired, http.MethodGet, "/admin/policy", nil), who)
	want := []string{
		`"kind":"admin.read","method":"POST","path":"/admin/access-check"`,
		`"kind":"admin.rejected","status":503,"method":"GET","path":"/admin/status","reason":"store"`,
		`"kind":"admin.denied","status":503,"method":"GET","path":"/admin/policy","actor":"alice"`,
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, _ := os.ReadFile(c.Audit().Path())
		missing := ""
		for _, part := range want {
			if !strings.Contains(string(data), part) {
				missing = part
			}
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no record with %s in:\n%s", missing, data)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A state-changing request outlives its client but not the admin listener's
// write limit.
func TestWritesDeadline(t *testing.T) {
	var live bool
	var deadline time.Time
	detached := detachWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		live = r.Context().Err() == nil
		deadline, _ = r.Context().Deadline()
	}))
	gone, cancel := context.WithCancel(t.Context())
	cancel()
	detached.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(gone, http.MethodPost, "/admin/candidates", nil))
	if !live || deadline.IsZero() || time.Until(deadline) > controller.AdminWriteTimeout {
		t.Fatalf("detached write: live %v, deadline %v", live, deadline)
	}
}
