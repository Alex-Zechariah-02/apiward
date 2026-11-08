// Server-side permissions and protected reads.

package integration

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Every sensitive read needs a session, every operation
// its own permission, and no response carries a secret.
func TestPermissionsAreServerSide(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	code, body, _ := e.HarnessCall(http.MethodPost, "/admin/candidates", string(gatewaytest.MustJSON(map[string]any{"policy": e.ProtectedPolicy()})),
		"If-Match", `"r1"`, "Idempotency-Key", "permission-candidate")
	if code != http.StatusCreated {
		t.Fatalf("staging: %d %s", code, body)
	}
	// Each addAdmin restarts the gateway, which ends earlier sessions, so all
	// administrators log in again after the last restart.
	_, readerPassword := addAdmin(e, gatewaytest.Binaries.Plain, "reader", "read")
	_, subjectsPassword := addAdmin(e, gatewaytest.Binaries.Plain, "subjects", "manage_subjects")
	auditor, _ := addAdmin(e, gatewaytest.Binaries.Plain, "auditor", "read_history")
	reader := e.MustLogin("reader", readerPassword)
	subjects := e.MustLogin("subjects", subjectsPassword)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)

	sensitive := []string{"/admin/status", "/admin/policy", "/admin/revisions", "/admin/revisions/1", "/admin/blocked-accounts",
		"/admin/keys", "/admin/candidates", "/admin/candidates/1", "/admin/history", "/admin/history/x", "/admin/session", "/admin/events", "/admin/traffic", "/admin/administrators"}
	for _, path := range sensitive {
		code, body, _ := e.AdminSend(http.MethodGet, path, "")
		if code != http.StatusUnauthorized || strings.TrimSpace(body) != `{"error":"unauthenticated"}` {
			t.Errorf("GET %s without a session: %d %s", path, code, body)
		}
	}

	type mutation struct{ method, path, body string }
	mutations := []mutation{
		{http.MethodPut, "/admin/blocked-accounts/mallory", `{"reason":"test containment"}`},
		{http.MethodDelete, "/admin/blocked-accounts/alice", ""},
		{http.MethodPost, "/admin/candidates", string(gatewaytest.MustJSON(map[string]any{"policy": e.ProtectedPolicy()}))},
		{http.MethodDelete, "/admin/candidates/1", ""},
		{http.MethodPost, "/admin/genesis", `{"candidate":1,"checksum":"x"}`},
		{http.MethodPost, "/admin/recovery-base", `{"candidate":1,"checksum":"x"}`},
	}
	for i, m := range mutations {
		for _, who := range []gatewaytest.AdminSession{reader, auditor} {
			header := []string{"If-Match", `"r1"`, "Idempotency-Key", fmt.Sprintf("permission-probe-%04d", i)}
			if code, _, _ := e.As(who, m.method, m.path, m.body, header...); code != http.StatusForbidden {
				t.Errorf("%s %s without its permission: %d", m.method, m.path, code)
			}
		}
	}
	if code, _, _ := e.As(subjects, http.MethodPost, "/admin/candidates", mutations[2].body, "If-Match", `"r1"`, "Idempotency-Key", "permission-subjects-1"); code != http.StatusForbidden {
		t.Errorf("manage_subjects stages a candidate: %d", code)
	}
	for who, paths := range map[string][]string{
		"reader":   {"/admin/history"},
		"subjects": {"/admin/status", "/admin/blocked-accounts", "/admin/history"},
		"auditor":  {"/admin/status", "/admin/policy"},
	} {
		session := map[string]gatewaytest.AdminSession{"reader": reader, "subjects": subjects, "auditor": auditor}[who]
		for _, path := range paths {
			if code, _, _ := e.As(session, http.MethodGet, path, ""); code != http.StatusForbidden {
				t.Errorf("%s GET %s: %d", who, path, code)
			}
		}
	}
	if code, _, _ := e.As(reader, http.MethodGet, "/admin/blocked-accounts", ""); code != http.StatusOK {
		t.Errorf("reader lists subjects: %d", code)
	}
	if code, _, _ := e.As(auditor, http.MethodGet, "/admin/history", ""); code != http.StatusOK {
		t.Errorf("auditor reads history: %d", code)
	}
	if s := e.Status(); s.Revision != 1 {
		t.Fatalf("refused mutations changed the revision to %d", s.Revision)
	}
	if code, body, _ := e.As(subjects, http.MethodPut, "/admin/blocked-accounts/carol", `{"reason":"test containment"}`,
		"If-Match", `"r1"`, "Idempotency-Key", "permission-subjects-2"); code != http.StatusOK {
		t.Fatalf("manage_subjects changes membership: %d %s", code, body)
	}

	// No read returns a credential, token, key or secret.
	forbidden := []string{"$argon2id", gatewaytest.HarnessPassword, harness.Cookie, reader.Cookie, reader.CSRF, "BEGIN", "PRIVATE", "secret"}
	for _, path := range sensitive {
		_, body, _ := e.As(harness, http.MethodGet, path, "")
		for _, value := range forbidden {
			if strings.Contains(body, value) {
				t.Errorf("GET %s returns %q", path, value)
			}
		}
	}
	if s := e.Status(); len(s.JWTKey) != 64 {
		t.Errorf("status key field %q is not a fingerprint", s.JWTKey)
	}
}

// Reads return the authoritative state with bounded pages.
func TestProtectedReads(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	seeded := e.ProtectedPolicy()
	gatewaytest.Seed(t, e.Database, seeded, gatewaytest.SeedOptions{})
	e.Start(gatewaytest.Binaries.Plain)
	before := e.Status()
	if before.Revision != 1 || before.State != store.ModeNormal {
		t.Fatalf("status %+v", before)
	}
	code, body, header := e.HarnessCall(http.MethodGet, "/admin/policy", "")
	if code != http.StatusOK || header.Get("ETag") != `"r1"` {
		t.Fatalf("policy: %d %s", code, header.Get("ETag"))
	}
	revision := fromJSON[store.RevisionInfo](t, body)
	if string(revision.Document) != string(gatewaytest.MustJSON(seeded)) || revision.Origin != "genesis" || revision.Checksum != store.DocumentChecksum(revision.Document) {
		t.Fatalf("policy read differs from the confirmed revision: %+v", revision)
	}

	for i := 1; i <= 5; i++ {
		draft := e.ProtectedPolicy()
		draft.Roles = append(draft.Roles, policy.Role{ID: fmt.Sprintf("OTHER%02d", i)})
		confirmPolicy(e, e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword), draft, int64(i), fmt.Sprintf("read-revision-%04d", i))
	}
	var listed []int64
	for after, pages := "", 0; ; pages++ {
		path := "/admin/revisions?limit=3"
		if after != "" {
			path += "&after=" + after
		}
		code, body, _ := e.HarnessCall(http.MethodGet, path, "")
		page := fromJSON[struct {
			Items []store.RevisionInfo `json:"items"`
			Next  string               `json:"next"`
		}](t, body)
		if code != http.StatusOK || len(page.Items) > 3 || pages > 3 {
			t.Fatalf("page %s: %d %s", path, code, body)
		}
		for _, s := range page.Items {
			listed = append(listed, s.ID)
		}
		if page.Next == "" {
			break
		}
		after = page.Next
	}
	if !slices.Equal(listed, []int64{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("listed %v", listed)
	}
	code, body, _ = e.HarnessCall(http.MethodGet, "/admin/revisions?limit=100", "")
	revisions := fromJSON[struct {
		Items []store.RevisionInfo `json:"items"`
	}](t, body)
	if code != http.StatusOK || len(revisions.Items) != 6 || revisions.Items[5].Origin != "publish" || revisions.Items[5].Actor != gatewaytest.HarnessAdmin {
		t.Fatalf("revisions: %d %s", code, body)
	}

	for _, path := range []string{"/admin/revisions?limit=0", "/admin/revisions?limit=101", "/admin/revisions?limit=x",
		"/admin/revisions?limit=99999999999999999999", "/admin/revisions?limit=1&limit=2", "/admin/revisions?sort=id",
		"/admin/revisions?after=-1", "/admin/revisions?after=01", "/admin/history?after=x", "/admin/candidates?limit=+5"} {
		if code, _, _ := e.HarnessCall(http.MethodGet, path, ""); code != http.StatusBadRequest {
			t.Errorf("GET %s: %d", path, code)
		}
	}
	for _, path := range []string{"/admin/revisions", "/admin/candidates", "/admin/activations", "/admin/overrides/history", "/admin/history"} {
		for _, query := range []string{"limit=1%zz", "after=%zz", "kind=cpa.confirm%zz", "limit=1;order=desc", "unknown=%zz", "order=%zz&limit=1"} {
			code, body, _ := e.HarnessCall(http.MethodGet, path+"?"+query, "")
			if code != http.StatusBadRequest || !strings.Contains(body, `"error":"bad_request"`) || !strings.Contains(body, `"field":"page"`) {
				t.Errorf("GET %s?%s: %d %s", path, query, code, body)
			}
		}
	}
	for _, path := range []string{"/admin/revisions/99", "/admin/revisions/0", "/admin/candidates/abc", "/admin/subjects/nobody", "/admin/history/none"} {
		if code, _, _ := e.HarnessCall(http.MethodGet, path, ""); code != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, code)
		}
	}
}
