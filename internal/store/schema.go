// Applying the schema migrations and verifying the schema.

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// CheckDatabaseSchema compares the database schema with the one the
// migrations up to version create.
func CheckDatabaseSchema(db *sql.DB, version int) error {
	actual, err := schemaFingerprint(db)
	if err != nil {
		return fmt.Errorf("%w: reading schema: %v", ErrUnavailable, err)
	}
	expected, err := referenceFingerprint(version)
	if err != nil {
		return fmt.Errorf("building reference schema: %w", err)
	}
	if actual != expected {
		return fmt.Errorf("%w: database schema differs from version %d", ErrUnavailable, version)
	}
	return nil
}

// ApplyMigrations applies the migrations after schema version from up to
// version to, and records the new version.
func ApplyMigrations(ctx context.Context, tx *sql.Tx, from, to int) error {
	for _, migration := range migrations[from:to] {
		if _, err := tx.ExecContext(ctx, migration); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", to))
	return err
}

// schemaFingerprint hashes every table, index and constraint definition.
func schemaFingerprint(db *sql.DB) (string, error) {
	rows, err := db.Query(`SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_schema ORDER BY type, name`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	sum := sha256.New()
	for rows.Next() {
		var kind, name, table, definition string
		if err := rows.Scan(&kind, &name, &table, &definition); err != nil {
			return "", err
		}
		fmt.Fprintf(sum, "%q %q %q %q\n", kind, name, table, definition)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// referenceFingerprint is the fingerprint of the migrations up to version
// applied to an empty in-memory database.
func referenceFingerprint(version int) (string, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return "", err
	}
	defer db.Close()
	// One connection: every further connection to :memory: would be another,
	// empty database.
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err := ApplyMigrations(ctx, tx, 0, version); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return schemaFingerprint(db)
}
