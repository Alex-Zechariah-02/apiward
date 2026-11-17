// The status and limits replies: build information, an unreadable stored
// authority and the confirmed size during recovery.

package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/storetest"
)

// A status read whose stored authority cannot be read says so, instead of
// omitting the confirmed and provisional revisions as though there were
// none; the facts that need no store read are still reported.
func TestStatusReportsUnreadableStoredAuthority(t *testing.T) {
	c := openController(t)
	read := func(ctx context.Context) map[string]any {
		t.Helper()
		reply := httptest.NewRecorder()
		testServer(c).handleStatus(reply, httptest.NewRequestWithContext(ctx, http.MethodGet, "/admin/status", nil), caller{})
		var status map[string]any
		if reply.Code != http.StatusOK || json.Unmarshal(reply.Body.Bytes(), &status) != nil {
			t.Fatalf("status: %d %s", reply.Code, reply.Body)
		}
		return status
	}
	readable := read(t.Context())
	if readable["confirmed"] == nil || readable["stored_authority"] != nil {
		t.Fatalf("readable authority: %v", readable)
	}
	// A cancelled request makes the store read fail without touching the
	// database.
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	unreadable := read(cancelled)
	if unreadable["stored_authority"] != "unreadable" || unreadable["confirmed"] != nil || unreadable["provisional"] != nil ||
		unreadable["state"] != readable["state"] || unreadable["admission"] != readable["admission"] || unreadable["audit_failed"] != readable["audit_failed"] {
		t.Fatalf("unreadable authority: %v, readable: %v", unreadable, readable)
	}
}

// The status reply names the build and every compiled-in control, sorted by
// phase and then ID.
func TestStatusBuild(t *testing.T) {
	c := openController(t)
	reply := httptest.NewRecorder()
	testServer(c).handleStatus(reply, httptest.NewRequest(http.MethodGet, "/admin/status", nil), caller{})
	var status struct{ Build buildInfo }
	if reply.Code != http.StatusOK || json.Unmarshal(reply.Body.Bytes(), &status) != nil {
		t.Fatalf("status: %d %s", reply.Code, reply.Body)
	}
	var listed []string
	for _, m := range status.Build.Modules {
		listed = append(listed, m.ID+":"+m.Phase)
	}
	if got := strings.Join(listed, " "); got != "jwt:identity rbac:authorise rate:traffic body:validate validation:validate" ||
		status.Build.Version == "" || !strings.HasPrefix(status.Build.Go, "go") {
		t.Fatalf("build: %+v", status.Build)
	}
}

// The limits report the confirmed document's size also while a restore's
// quarantine waits for recovery, which keeps the confirmed revision.
func TestLimitsConfirmedBytes(t *testing.T) {
	c := openSeeded(t, storetest.Options{}, func(database string) {
		db, err := sql.Open("sqlite", store.DatabaseURI(database))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(`UPDATE deployment SET mode = 'recovery_required', recovery_episode = ?`, strings.Repeat("ab", 16)); err != nil {
			t.Fatal(err)
		}
	})
	used, err := testServer(c).confirmedBytes(t.Context())
	if err != nil || used == 0 {
		t.Fatalf("confirmed bytes in recovery: %d, %v", used, err)
	}
}
