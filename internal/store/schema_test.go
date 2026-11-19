// Schema checks: the version is the number of migrations, and the schema
// comparison ignores quoting and spacing but names a real difference.

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestDatabaseVersion(t *testing.T) {
	if DatabaseVersion != len(migrations) {
		t.Fatalf("DatabaseVersion %d, %d migrations", DatabaseVersion, len(migrations))
	}
	if err := ApplyMigrations(context.Background(), nil, 0, len(migrations)+1); err == nil {
		t.Fatal("migrations past the last one were not refused")
	}
}

// memory applies the migrations, each changed by rewrite, to a new in-memory
// database.
func memory(t *testing.T, rewrite func(string) string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	for _, migration := range migrations {
		if _, err := db.Exec(rewrite(migration)); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestSchemaComparison(t *testing.T) {
	ctx := context.Background()
	respaced := memory(t, func(s string) string {
		s = strings.ReplaceAll(s, "\n\t", "\n    ")
		s = strings.ReplaceAll(s, " (", "(")
		return strings.ReplaceAll(s, "CREATE TABLE deployment", `CREATE TABLE "deployment"`)
	})
	if err := checkSchema(ctx, respaced, DatabaseVersion); err != nil {
		t.Fatalf("the same schema written differently: %v", err)
	}
	widened := memory(t, func(s string) string {
		return strings.Replace(s, "name TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 64)", "name TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 65)", 1)
	})
	err := checkSchema(ctx, widened, DatabaseVersion)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "table administrator") {
		t.Fatalf("a changed constraint: %v", err)
	}
}
