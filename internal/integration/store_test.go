// The schema an installation creates.

package integration

import (
	"slices"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
)

// An installed database has exactly the current schema: the eleven STRICT
// tables, their keys and constraints, the activation and override indexes and
// triggers, WAL journaling and user_version 5, and nothing else.
func TestInstalledSchema(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "install", "--admin", "root"); code != 0 {
		t.Fatalf("install exited %d: %s", code, out)
	}
	db := gatewaytest.Inspect(t, e.Database)

	rows, err := db.Query(`SELECT name, strict FROM pragma_table_list WHERE schema = 'main' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		var strict int
		if err := rows.Scan(&name, &strict); err != nil {
			t.Fatal(err)
		}
		if strict != 1 {
			t.Errorf("table %s is not STRICT", name)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	want := []string{"activation", "administrator", "base", "blocked_account", "blocked_address", "candidate", "control_result", "deployment", "enrolment", "override", "revision", "transition"}
	if !slices.Equal(tables, want) {
		t.Fatalf("tables %v, want %v", tables, want)
	}
	// Besides those SQLite creates for primary keys and UNIQUE, the only
	// indexes and triggers guard the provisional and override lifecycles.
	explicit, err := db.Query(`SELECT name FROM sqlite_schema WHERE type IN ('index', 'trigger', 'view') AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for explicit.Next() {
		var name string
		explicit.Scan(&name)
		names = append(names, name)
	}
	if err := explicit.Err(); err != nil {
		t.Fatal(err)
	}
	explicit.Close()
	if want := []string{"activation_final", "activation_fixed", "activation_kept", "activation_unresolved", "base_provisional",
		"override_active_target", "override_final", "override_fixed", "override_kept", "override_resolution", "override_shared"}; !slices.Equal(names, want) {
		t.Fatalf("explicit indexes and triggers %v, want %v", names, want)
	}
	// Of the override's UNIQUE constraints only creation remains on its
	// column; a resolution is unique only among revocations and expiries.
	if n := gatewaytest.Count(t, db, `SELECT COUNT(*) FROM pragma_index_list('override') WHERE origin = 'u'`); n != 1 {
		t.Fatalf("override has %d UNIQUE column constraints, want 1", n)
	}
	if n := gatewaytest.Count(t, db, `SELECT COUNT(*) FROM pragma_index_info('sqlite_autoindex_override_1') WHERE name = 'creation'`); n != 1 {
		t.Fatal("the override UNIQUE column constraint is not on creation")
	}
	foreignKeys := map[string]int{"revision": 1, "base": 2, "candidate": 1, "transition": 2, "activation": 4, "override": 3, "blocked_account": 1, "blocked_address": 1, "control_result": 1}
	for table, want := range foreignKeys {
		if n := gatewaytest.Count(t, db, `SELECT COUNT(*) FROM pragma_foreign_key_list(?)`, table); n != want {
			t.Errorf("table %s has %d foreign keys, want %d", table, n, want)
		}
	}
	if n := gatewaytest.Count(t, db, `PRAGMA user_version`); n != 6 {
		t.Fatalf("user_version %d", n)
	}
	var journal string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal mode %q %v", journal, err)
	}
	var check string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity check %q %v", check, err)
	}
	if n := gatewaytest.Count(t, db, `SELECT COUNT(*) FROM pragma_foreign_key_check`); n != 0 {
		t.Fatalf("%d foreign key violations", n)
	}
	// The install transition is recorded and audited.
	if n := gatewaytest.Count(t, db, `SELECT COUNT(*) FROM transition WHERE kind = 'operator.install' AND outcome = 'committed' AND audited_at IS NOT NULL`); n != 1 {
		t.Fatalf("%d audited install transitions", n)
	}
}
