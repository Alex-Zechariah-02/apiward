// Incremental auto-vacuum on new stores, migrated stores and after pruning.

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pragmaInt(t *testing.T, s *DB, pragma string) int {
	t.Helper()
	var v int
	if err := s.db.QueryRow("PRAGMA " + pragma).Scan(&v); err != nil {
		t.Fatalf("PRAGMA %s: %v", pragma, err)
	}
	return v
}

func TestNewStoreUsesIncrementalVacuum(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "new.db")
	s, err := CreateStore(ctx, path, strings.Repeat("a", 32),
		Enrolment{Name: "admin", Secret: strings.Repeat("b", 64), Permissions: PermAll, ExpiresAt: now.Add(time.Hour)},
		TransitionRecord{ID: "install-1", Kind: "operator.install", Actor: "op", Target: "admin", Digest: "d"},
		now)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := pragmaInt(t, s, "auto_vacuum"); got != 2 {
		t.Fatalf("PRAGMA auto_vacuum = %d, want 2 (INCREMENTAL)", got)
	}
}

func TestMigrateConvertsAutoVacuum(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "old.db")
	if err := CreatePrivate(path); err != nil {
		t.Fatal(err)
	}
	db, err := Connect(path, "WAL")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	prev := DatabaseVersion - 1
	if err := ApplyMigrations(ctx, tx, 0, prev); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO deployment (id, installation, mode, high_water) VALUES (1, ?, ?, ?)`, strings.Repeat("c", 32), ModeBootstrap, now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO base (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != 0 {
		t.Fatalf("seeded auto_vacuum = %d, want 0", before)
	}
	db.Close()

	s, from, err := OpenForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if from != prev {
		t.Fatalf("from = %d, want %d", from, prev)
	}
	if err := s.Migrate(ctx, from, TransitionRecord{ID: "mig-1", Kind: "operator.migrate", Actor: "op", Target: "v", Digest: "d"}, now); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if got := pragmaInt(t, s, "user_version"); got != DatabaseVersion {
		t.Fatalf("PRAGMA user_version = %d, want %d", got, DatabaseVersion)
	}
	if got := pragmaInt(t, s, "auto_vacuum"); got != 2 {
		t.Fatalf("PRAGMA auto_vacuum after migrate = %d, want 2 (INCREMENTAL)", got)
	}
}

func TestPruneReturnsPages(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "prune.db")
	s, err := CreateStore(ctx, path, strings.Repeat("d", 32),
		Enrolment{Name: "admin", Secret: strings.Repeat("e", 64), Permissions: PermAll, ExpiresAt: now.Add(time.Hour)},
		TransitionRecord{ID: "install-1", Kind: "operator.install", Actor: "op", Target: "admin", Digest: "d"},
		now)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	doc := []byte(`{"pad":"` + strings.Repeat("x", 4000) + `"}`)
	checksum := DocumentChecksum(doc)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	const total = 2000
	for i := 1; i <= total; i++ {
		ts := now.Add(time.Duration(i) * time.Millisecond).UnixMilli()
		if _, err := tx.ExecContext(ctx, `INSERT INTO revision (id, origin, document, checksum, actor, created_at) VALUES (?, 'publish', ?, ?, 'admin', ?)`, i, doc, checksum, ts); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO transition (id, kind, actor, target, digest, outcome, reason, result_revision, committed_at, audited_at) VALUES (?, 'policy.publish', 'admin', 't', 'd', 'committed', '', ?, ?, ?)`, fmt.Sprintf("t-%d", i), i, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE base SET confirmed = ? WHERE id = 1`, total); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE deployment SET mode = ? WHERE id = 1`, ModeNormal); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	commitTime := now.Add(time.Minute)
	_, err = s.CommitRevision(ctx,
		TransitionRecord{ID: "t-prune", Kind: "policy.publish", Actor: "admin", Target: "t", Digest: "d"},
		RevisionChange{Origin: "publish", Document: doc, Actor: "admin", Mode: ModeNormal, Keep: 100},
		commitTime)
	if err != nil {
		t.Fatalf("CommitRevision: %v", err)
	}

	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if infoAfter.Size() >= infoBefore.Size() {
		t.Fatalf("database did not shrink after pruning: before=%d after=%d", infoBefore.Size(), infoAfter.Size())
	}
}
