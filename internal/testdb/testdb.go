// Package testdb is test support only, never imported by production code: it
// seeds a disposable gateway database whose confirmed revision is a given
// policy, optionally with a provisional revision and its deadline and an
// administrator, reads single values back for assertions, and builds the
// small test policies the seeds use. Unit tests of the packages that open a
// deployment use it instead of the operator's install command.
package testdb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Options adds a provisional revision 2, made from candidate 1, whose
// deadline is Deadline (nil Provisional: only the confirmed base), and an
// active administrator named Administrator with every permission and no
// usable password (empty: none).
type Options struct {
	Provisional   *policy.Policy
	Deadline      time.Time
	Administrator string
}

// Seed creates the database at path in normal mode, at the current schema
// version, with p as its confirmed revision 1.
func Seed(t testing.TB, path string, p policy.Policy, opts Options) {
	t.Helper()
	db, err := sql.Open("sqlite", store.DatabaseURI(path)+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := store.ApplyMigrations(ctx, tx, 0, store.DatabaseVersion); err != nil {
		t.Fatal(err)
	}
	installation := make([]byte, 16)
	rand.Read(installation)
	statements := [][]any{
		{`INSERT INTO deployment (id, installation, mode, recovery_episode, high_water) VALUES (1, ?, ?, NULL, ?)`,
			hex.EncodeToString(installation), store.ModeNormal, time.Now().UnixMilli()},
		append([]any{`INSERT INTO revision VALUES (1, NULL, 'genesis', ?, ?, 'seed', ?)`}, revision(p)...),
		{`INSERT INTO base VALUES (1, 1, NULL, NULL)`},
	}
	if opts.Administrator != "" {
		statements = append(statements, []any{`INSERT INTO administrator VALUES (?, ?, '$argon2id$unusable', 'active', 1, ?)`,
			opts.Administrator, store.PermAll, time.Now().UnixMilli()})
	}
	if opts.Provisional != nil {
		deadline := opts.Deadline.UnixMilli()
		statements = append(statements,
			append([]any{`INSERT INTO candidate VALUES (1, 1, ?, ?, 0, 'established', 'seed', ?)`}, revision(*opts.Provisional)...),
			append([]any{`INSERT INTO revision VALUES (2, 1, 'publish', ?, ?, 'seed', ?)`}, revision(*opts.Provisional)...),
			[]any{`INSERT INTO activation (revision, candidate, rollback_target, deadline, activated_at, actor) VALUES (2, 1, 1, ?, ?, 'seed')`,
				deadline, deadline - time.Minute.Milliseconds()},
			[]any{`UPDATE base SET provisional = 2, deadline = ? WHERE id = 1`, deadline},
		)
	}
	for _, s := range statements {
		if _, err := tx.ExecContext(ctx, s[0].(string), s[1:]...); err != nil {
			t.Fatalf("seeding database: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// revision is the document, checksum and creation time columns of p.
func revision(p policy.Policy) []any {
	document, _ := json.Marshal(p)
	return []any{document, store.DocumentChecksum(document), time.Now().UnixMilli()}
}

// Int reads the single integer that query returns from the database at path.
func Int(t testing.TB, path, query string) int {
	t.Helper()
	db, err := sql.Open("sqlite", store.DatabaseURI(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// AnyObject is a body schema that accepts any JSON object.
const AnyObject = `{"type":"object","additionalProperties":true}`

// JSONBody is a body rule of at most maxBytes checked against schema.
func JSONBody(maxBytes int64, schema string) *policy.BodyRule {
	return &policy.BodyRule{MaxBytes: maxBytes, Schema: json.RawMessage(schema)}
}

// Rate is a per-account sliding-window rule of count requests per window.
func Rate(count, windowSeconds int64) *policy.RateRule {
	return &policy.RateRule{Algorithm: "sliding-window", Count: count, WindowSeconds: windowSeconds, Key: "subject"}
}

// Policy routes API a to upstream A and, withB, API b to upstream B, with the
// operations read-a, write-a, denied and (withB) read-b; the upstream
// addresses are never dialled.
func Policy(withB bool) policy.Policy {
	p := policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "A", Dial: "127.0.0.1:1"}, {ID: "B", Dial: "127.0.0.1:2"}},
		APIs:          []policy.API{{ID: "a", Upstream: "A"}, {ID: "b", Upstream: "B"}, {ID: "d", Upstream: "A"}},
		Operations: []policy.Operation{
			{ID: "read-a", API: "a", Method: "GET", Target: "/a/*", Access: "allow", Auth: "none"},
			{ID: "write-a", API: "a", Method: "POST", Target: "/a/item", Access: "allow", Auth: "none", Body: JSONBody(1024, AnyObject)},
			{ID: "denied", API: "d", Method: "GET", Target: "/d", Access: "deny", Auth: "none"},
		},
	}
	if withB {
		p.Operations = append(p.Operations, policy.Operation{ID: "read-b", API: "b", Method: "GET", Target: "/b/*", Access: "allow", Auth: "none"})
	}
	return p
}

// Protected is Policy(true) with authentication on every allowed operation
// and the roles READER and WRITER.
func Protected() policy.Policy {
	p := Policy(true)
	for i := range p.Operations {
		if p.Operations[i].ID != "denied" {
			p.Operations[i].Auth = "required"
		}
	}
	p.Roles = []policy.Role{{ID: "READER"}, {ID: "WRITER"}}
	p.Permits = []policy.Permit{
		{Role: "READER", Operation: "read-a"},
		{Role: "WRITER", Operation: "read-a"},
		{Role: "WRITER", Operation: "write-a"},
		{Role: "READER", Operation: "read-b"},
	}
	return p
}
