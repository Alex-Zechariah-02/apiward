// Migration from the first database version.

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// A database of the previous schema version is not served until the
// local migrate command upgrades it. The command refuses a database held by a
// running gateway, a database whose schema is not exactly its version's, and
// one holding a provisional base the new schema could not describe; an
// interrupted migration leaves the earlier version intact.
func TestMigrateFromVersionOne(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{Version: 1})
	e.Start(gatewaytest.Binaries.Plain)
	if health := e.Health(); health != "unavailable" {
		t.Fatalf("health %q on a version 1 database", health)
	}
	if reason := e.UnavailableReason(); !strings.Contains(reason, "schema version 1") || !strings.Contains(reason, "migrate") {
		t.Fatalf("reason %q", reason)
	}
	if code, _ := e.Get("/a/x", "Authorization", "Bearer "+gatewaytest.Issuer.TokenFor(t, "alice")); code != http.StatusServiceUnavailable {
		t.Fatalf("data plane on a version 1 database: %d", code)
	}
	// A gateway that refused the database holds no lock on it, so, as for
	// every operator command, the operator stops it first.
	e.Stop()

	if out, code := e.RunOperator(gatewaytest.Binaries.Fault, []string{"GATEWAY_FAULT=migrate-before-commit"}, "migrate"); code != crashExit {
		t.Fatalf("interrupted migrate exited %d: %s", code, out)
	}
	if n := gatewaytest.QueryInt(t, e.Database, `PRAGMA user_version`); n != 1 {
		t.Fatalf("user_version %d after an interrupted migration", n)
	}
	out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "migrate")
	if code != 0 || !strings.Contains(out, fmt.Sprintf("from schema version 1 to %d", store.DatabaseVersion)) {
		t.Fatalf("migrate exited %d: %s", code, out)
	}
	if n := gatewaytest.QueryInt(t, e.Database, `SELECT COUNT(*) FROM transition WHERE kind = 'operator.migrate' AND outcome = 'committed' AND audited_at IS NOT NULL`); n != 1 {
		t.Fatalf("%d recorded migrations", n)
	}
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "migrate"); code == 0 || !strings.Contains(out, "cannot be migrated") {
		t.Fatalf("second migrate: %d %s", code, out)
	}

	// The migrated database serves its confirmed base and supports the
	// lifecycle.
	e.Start(gatewaytest.Binaries.Plain)
	harness := e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)
	if s := e.Status(); s.State != store.ModeNormal || s.Revision != 1 || s.Confirmed != 1 {
		t.Fatalf("status after migration: %+v", s)
	}
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "migrate"); code == 0 || !strings.Contains(out, "held by another gateway process") {
		t.Fatalf("migrate while a gateway holds the database: %d %s", code, out)
	}
	e.ProvisionalFrom(harness, e.CpaCandidate(), 1, 60, "after-migration-01")
	expectEnforced(e, true, "")
	if code, _, body := e.Resolve(harness, "rollback", 2, `"r1"`, "after-migration-rollback"); code != http.StatusOK {
		t.Fatalf("rollback after migration: %d %s", code, body)
	}
	events := e.EventsWhen(func(events []map[string]any) bool { return gatewaytest.CountKind(events, "transition.committed") > 0 })
	if findTransition(events, "transition.committed", queryLatestMigration(t, e)) == nil {
		t.Fatal("no committed migration event")
	}

	refusals := []struct {
		name    string
		prepare func(path string)
		reason  string
	}{
		{"provisional base", func(path string) {
			candidate := e.CpaCandidate()
			gatewaytest.Seed(t, path, e.ProtectedPolicy(), gatewaytest.SeedOptions{Version: 1, Provisional: &candidate, Deadline: time.Now().Add(time.Hour)})
		}, "provisional base"},
		{"altered schema", func(path string) {
			gatewaytest.Seed(t, path, e.ProtectedPolicy(), gatewaytest.SeedOptions{Version: 1})
			db := gatewaytest.Inspect(t, path)
			mustExec(t, db, `CREATE INDEX extra ON revision (actor)`)
			db.Close()
		}, "schema differs"},
	}
	for _, r := range refusals {
		other := gatewaytest.NewEnv(t)
		r.prepare(other.Database)
		before := gatewaytest.FileSHA256(t, other.Database)
		if out, code := other.RunOperator(gatewaytest.Binaries.Plain, nil, "migrate"); code == 0 || !strings.Contains(out, r.reason) {
			t.Errorf("%s: migrate exited %d: %s", r.name, code, out)
		}
		if after := gatewaytest.FileSHA256(t, other.Database); after != before {
			t.Errorf("%s: a refused migration changed the database", r.name)
		}
	}
}

// queryLatestMigration returns the identity of the recorded migration, read
// through the running gateway's history.
func queryLatestMigration(t *testing.T, e *gatewaytest.Env) string {
	t.Helper()
	for _, h := range historyItems(e, e.MustLogin(gatewaytest.HarnessAdmin, gatewaytest.HarnessPassword)) {
		if h.Kind == "operator.migrate" {
			return h.ID
		}
	}
	t.Fatal("no migration in the history")
	return ""
}
