// Offline migration of older databases.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/disk"
	"github.com/Alex-Zechariah-02/apiward/internal/fault"
)

// OpenForMigration opens a database at an earlier schema version and returns
// it with that version. A database whose schema is not exactly its version's,
// or a version 1 database with a provisional base, which has no activation
// record to migrate, is refused unchanged.
func OpenForMigration(path string) (*DB, int, error) {
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		return nil, 0, fmt.Errorf("database %q missing or empty", path)
	}
	db, err := Connect(path, "WAL")
	if err != nil {
		return nil, 0, err
	}
	version, err := migratable(db)
	if err != nil {
		db.Close()
		return nil, version, err
	}
	return &DB{db: db, path: path}, version, nil
}

// vacuumHeadroom is the extra free space required beyond the database file
// size before running VACUUM to enable incremental auto-vacuum.
const vacuumHeadroom = 64 << 20

// enableIncrementalVacuum converts an existing database to incremental
// auto-vacuum outside any transaction when PRAGMA auto_vacuum is not 2.
// Before VACUUM rewrites the file, it validates the migration in a rolled-back
// transaction so a damaged database is refused unchanged.
func (s *DB) enableIncrementalVacuum(ctx context.Context, from int) error {
	var mode int
	if err := s.db.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&mode); err != nil {
		return fmt.Errorf("reading auto_vacuum mode: %w", err)
	}
	if mode == 2 {
		return nil
	}
	if err := s.validateMigration(ctx, from); err != nil {
		return err
	}
	if s.path != "" {
		realPath := s.path
		if resolved, err := filepath.EvalSymlinks(s.path); err == nil {
			realPath = resolved
		}
		info, err := os.Stat(realPath)
		if err != nil {
			return fmt.Errorf("sizing database for auto-vacuum conversion: %w", err)
		}
		need := info.Size() + vacuumHeadroom
		space, err := disk.Of(filepath.Dir(realPath))
		if err != nil {
			return fmt.Errorf("checking free space for auto-vacuum conversion: %w", err)
		}
		if space.Free >= 0 && space.Free < need {
			return fmt.Errorf("insufficient free space for auto-vacuum conversion: need %d bytes, have %d bytes free", need, space.Free)
		}
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA auto_vacuum = INCREMENTAL"); err != nil {
		return fmt.Errorf("setting auto_vacuum: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("vacuuming database for auto-vacuum conversion: %w", err)
	}
	return nil
}

// validateMigration runs the schema migration and integrity checks inside a
// transaction that always rolls back, leaving the database file untouched.
func (s *DB) validateMigration(ctx context.Context, from int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return applyAndCheck(ctx, tx, from)
}

func applyAndCheck(ctx context.Context, tx *sql.Tx, from int) error {
	if err := ApplyMigrations(ctx, tx, from, DatabaseVersion); err != nil {
		return err
	}
	if err := checkSchema(ctx, tx, DatabaseVersion); err != nil {
		return err
	}
	var check string
	if err := tx.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		return fmt.Errorf("integrity check failed: %v %s", err, check)
	}
	var violations int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_foreign_key_check").Scan(&violations); err != nil {
		return err
	}
	if violations != 0 {
		return fmt.Errorf("foreign key check failed: %d violations", violations)
	}
	return nil
}

func migratable(db *sql.DB) (int, error) {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return 0, err
	}
	if version < 1 || version >= DatabaseVersion {
		return version, fmt.Errorf("database schema version %d cannot be migrated to %d", version, DatabaseVersion)
	}
	if err := CheckDatabaseSchema(db, version); err != nil {
		return version, err
	}
	if version >= 2 {
		return version, nil
	}
	var provisional sql.NullInt64
	if err := db.QueryRow(`SELECT provisional FROM base WHERE id = 1`).Scan(&provisional); err != nil {
		return version, err
	}
	if provisional.Valid {
		return version, errors.New("the database has a provisional base without an activation record; it cannot be migrated")
	}
	return version, nil
}

// Migrate applies the migrations from version to the current one in a single
// transaction with the operator transition, then checks the result. The
// migrated schema is compared with the current one before the commit. A
// database whose migrated content fails the integrity or foreign key check is
// left at its earlier version: the checks run before the commit, so damaged
// rows are refused rather than carried into the new version.
func (s *DB) Migrate(ctx context.Context, from int, t TransitionRecord, now time.Time) error {
	if err := s.enableIncrementalVacuum(ctx, from); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := applyAndCheck(ctx, tx, from); err != nil {
		return err
	}
	if err := insertCommitted(ctx, tx, t, now); err != nil {
		return err
	}
	fault.CrashPoint("migrate-before-commit")
	if err := tx.Commit(); err != nil {
		return err
	}
	return Verify(s.db)
}
