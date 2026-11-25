// Permit-use store migration and 30-day window pruning tests.

package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrateAddsPermitUseTables(t *testing.T) {
	t.Parallel()
	if DatabaseVersion < 10 {
		t.Fatalf("DatabaseVersion = %d, want >= 10", DatabaseVersion)
	}
	path := filepath.Join(t.TempDir(), "v9.db")
	db, err := Connect(path, "WAL")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(t.Context(), tx, 0, 9); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	if _, err := tx.Exec(`INSERT INTO deployment (id, installation, mode, high_water) VALUES (1, '0123456789abcdef0123456789abcdef', 'bootstrap_locked', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO base (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, from, err := OpenForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if from != 9 {
		t.Fatalf("from = %d, want 9", from)
	}
	tr := TransitionRecord{ID: "operator:migrate:10:test", Kind: "operator.migrate", Actor: "operator:test", Target: "schema version 10", Digest: "operator"}
	if err := st.Migrate(t.Context(), from, tr, time.Now()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, table := range []string{"permit_use", "permit_use_window"} {
		var count int
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatalf("table %s missing after migration: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("table %s has %d rows, want 0", table, count)
		}
	}
}

func TestPermitUseWindowDropsOldRows(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "permit.db")
	st, err := CreateStore(t.Context(), path, "0123456789abcdef0123456789abcdef",
		Enrolment{Name: "root", Secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Permissions: PermAll, ExpiresAt: time.Now().Add(time.Hour)},
		TransitionRecord{ID: "operator:install:1", Kind: "operator.install", Actor: "operator:test", Target: "root", Digest: "operator"},
		time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	cutoff := now.Add(-30 * 24 * time.Hour)
	err = st.ReplacePermitUse(t.Context(), PermitUseState{
		Since:    now.Add(-2 * time.Hour),
		Requests: 600,
		Used: []PermitUseRow{
			{Role: "READER", Operation: "old-op", LastUsed: now.Add(-31 * 24 * time.Hour)},
			{Role: "READER", Operation: "new-op", LastUsed: now.Add(-time.Hour)},
		},
	}, cutoff)
	if err != nil {
		t.Fatalf("ReplacePermitUse: %v", err)
	}
	loaded, err := st.LoadPermitUse(t.Context())
	if err != nil {
		t.Fatalf("LoadPermitUse: %v", err)
	}
	if loaded.Requests != 600 || !loaded.Since.Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("loaded window = %+v", loaded)
	}
	if len(loaded.Used) != 1 || loaded.Used[0].Operation != "new-op" {
		t.Fatalf("loaded rows = %+v, want only new-op (old-op dropped)", loaded.Used)
	}
	var name string
	if err := st.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='permit_use'`).Scan(&name); err != nil {
		if err == sql.ErrNoRows {
			t.Fatalf("permit_use table does not exist")
		}
		t.Fatal(err)
	}
}
