// Applying the schema migrations and verifying the schema. The schema is
// compared by structure and by normalised definition text, so the same
// schema written with other quoting or spacing (as another SQLite version
// may store it after ALTER TABLE ... RENAME) still matches.

package store

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
)

// CheckDatabaseSchema compares the database schema with the one the
// migrations up to version create.
func CheckDatabaseSchema(db *sql.DB, version int) error {
	return checkSchema(context.Background(), db, version)
}

// checkSchema compares the schema q sees, a connection or a transaction, with
// the reference one, naming the first object that differs.
func checkSchema(ctx context.Context, q querier, version int) error {
	actual, err := schemaObjects(ctx, q)
	if err != nil {
		return fmt.Errorf("%w: reading schema: %v", ErrUnavailable, err)
	}
	expected, err := referenceObjects(version)
	if err != nil {
		return fmt.Errorf("building reference schema: %w", err)
	}
	names := slices.Collect(maps.Keys(actual))
	for name := range expected {
		if _, found := actual[name]; !found {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		if actual[name] != expected[name] {
			return fmt.Errorf("%w: database schema differs from version %d at %s", ErrUnavailable, version, name)
		}
	}
	return nil
}

// ApplyMigrations applies the migrations after schema version from up to
// version to, and records the new version.
func ApplyMigrations(ctx context.Context, tx *sql.Tx, from, to int) error {
	if from < 0 || from > to || to > len(migrations) {
		return fmt.Errorf("no migrations from schema version %d to %d", from, to)
	}
	for _, migration := range migrations[from:to] {
		if _, err := tx.ExecContext(ctx, migration); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", to))
	return err
}

// structure lists, per kind of schema object, the pragma rows that describe
// it beyond its definition text: columns, foreign keys and indexes of a
// table, columns of an index.
var structure = map[string][]string{
	"table": {
		"SELECT cid, name, type, \"notnull\", coalesce(dflt_value, ''), pk, hidden FROM pragma_table_xinfo(?) ORDER BY cid",
		"SELECT id, seq, \"table\", \"from\", coalesce(\"to\", ''), on_update, on_delete, \"match\" FROM pragma_foreign_key_list(?) ORDER BY id, seq",
		"SELECT name, \"unique\", origin, partial FROM pragma_index_list(?) ORDER BY name",
	},
	"index": {
		"SELECT seqno, cid, coalesce(name, ''), \"desc\", coll, key FROM pragma_index_xinfo(?) ORDER BY seqno",
	},
}

// schemaObjects describes every table, index and trigger, keyed by kind and
// name: its normalised definition and its structure rows.
func schemaObjects(ctx context.Context, q querier) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_schema ORDER BY type, name`)
	if err != nil {
		return nil, err
	}
	type object struct{ kind, name, table, definition string }
	var list []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.kind, &o.name, &o.table, &o.definition); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	objects := make(map[string]string, len(list))
	for _, o := range list {
		var text strings.Builder
		fmt.Fprintf(&text, "%s %s\n", o.table, normalise(o.definition))
		for _, query := range structure[o.kind] {
			if err := describe(ctx, q, query, o.name, &text); err != nil {
				return nil, err
			}
		}
		objects[o.kind+" "+o.name] = text.String()
	}
	return objects, nil
}

// describe appends the rows query returns for name to text.
func describe(ctx context.Context, q querier, query, name string, text *strings.Builder) error {
	rows, err := q.QueryContext(ctx, query, name)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(pointers...); err != nil {
			return err
		}
		fmt.Fprintf(text, "%v\n", values)
	}
	return rows.Err()
}

// normalise drops identifier quotes and the spacing SQLite keeps verbatim:
// runs of white space become one space, and a space beside punctuation goes.
func normalise(definition string) string {
	definition = strings.NewReplacer("\"", "", "`", "").Replace(definition)
	fields := strings.Fields(definition)
	var out strings.Builder
	for i, field := range fields {
		if i > 0 && word(fields[i-1], true) && word(field, false) {
			out.WriteByte(' ')
		}
		out.WriteString(field)
	}
	return out.String()
}

// word reports whether the last (end) or first rune of field is part of a
// word, so a space beside it separates two words and is kept.
func word(field string, end bool) bool {
	runes := []rune(field)
	r := runes[0]
	if end {
		r = runes[len(runes)-1]
	}
	return r == '_' || r == '\'' || r == '$' || r == '%' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// referenceObjects describes the schema of the migrations up to version
// applied to an empty in-memory database.
func referenceObjects(version int) (map[string]string, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// One connection: every further connection to :memory: would be another,
	// empty database.
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := ApplyMigrations(ctx, tx, 0, version); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return schemaObjects(ctx, db)
}
