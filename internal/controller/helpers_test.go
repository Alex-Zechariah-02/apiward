// Fixtures for the controller's unit tests: a disposable seeded deployment,
// its configuration, test policies and override requests.

package controller

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
	"github.com/Alex-Zechariah-02/apiward/internal/testissuer"
)

var issuer = testissuer.New(2048)

// env is one disposable deployment directory.
type env struct {
	t        *testing.T
	dir      string
	database string
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "issuer.pem"), issuer.PublicPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, dir: dir, database: filepath.Join(dir, "gateway.db")}
}

// controllerConfig never starts its admin address: tests call no Start.
func (e *env) controllerConfig() Config {
	return Config{
		Database:    e.database,
		AuditLog:    filepath.Join(e.dir, "audit.log"),
		AdminListen: "127.0.0.1:1",
		JWT: pipeline.TrustConfig{Issuer: testissuer.Name, Audience: testissuer.Audience,
			Keys: []pipeline.VerificationKey{{Kid: "test-a", PublicKeyFile: filepath.Join(e.dir, "issuer.pem")}}},
	}
}

// own prepares and opens a controller for cfg and stops it when the test ends.
func (e *env) own(cfg Config) *Controller {
	e.t.Helper()
	c, err := Prepare(cfg, slog.New(slog.DiscardHandler))
	if err == nil {
		err = c.Open()
	}
	if err != nil {
		e.t.Fatalf("opening the controller: %v", err)
	}
	e.t.Cleanup(func() { c.Stop() })
	return c
}

type seedOptions struct {
	provisional *policy.Policy
	deadline    time.Time
}

// seed creates a database in normal mode whose confirmed revision 1 is p and,
// when opts names one, provisional revision 2 with its deadline.
func seed(t *testing.T, path string, p policy.Policy, opts seedOptions) {
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
		append([]any{`INSERT INTO revision VALUES (1, NULL, 'genesis', ?, ?, 'seed', ?)`}, revisionArgs(p)...),
		{`INSERT INTO base VALUES (1, 1, NULL, NULL)`},
	}
	if opts.provisional != nil {
		deadline := opts.deadline.UnixMilli()
		statements = append(statements,
			append([]any{`INSERT INTO candidate VALUES (1, 1, ?, ?, 0, 'established', 'seed', ?)`}, revisionArgs(*opts.provisional)...),
			append([]any{`INSERT INTO revision VALUES (2, 1, 'publish', ?, ?, 'seed', ?)`}, revisionArgs(*opts.provisional)...),
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

func revisionArgs(p policy.Policy) []any {
	document, _ := json.Marshal(p)
	return []any{document, store.DocumentChecksum(document), time.Now().UnixMilli()}
}

func queryInt(t *testing.T, path, query string) int {
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

const anyObject = `{"type":"object","additionalProperties":true}`

func jsonBody(maxBytes int64, schema string) *policy.BodyRule {
	return &policy.BodyRule{MaxBytes: maxBytes, Schema: json.RawMessage(schema)}
}

func rate(count, windowSeconds int64) *policy.RateRule {
	return &policy.RateRule{Algorithm: "sliding-window", Count: count, WindowSeconds: windowSeconds, Key: "subject"}
}

// basePolicy routes API a to upstream A and, withB, API b to upstream B; no
// upstream is dialled by these tests.
func basePolicy(withB bool) policy.Policy {
	p := policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Profile:       policy.ProfileCore,
		Upstreams:     []policy.Upstream{{ID: "A", Dial: "127.0.0.1:1"}, {ID: "B", Dial: "127.0.0.1:2"}},
		APIs:          []policy.API{{ID: "a", Upstream: "A"}, {ID: "b", Upstream: "B"}, {ID: "d", Upstream: "A"}},
		Operations: []policy.Operation{
			{ID: "read-a", API: "a", Method: "GET", Target: "/a/*", Access: "allow", Auth: "none"},
			{ID: "write-a", API: "a", Method: "POST", Target: "/a/item", Access: "allow", Auth: "none", Body: jsonBody(1024, anyObject)},
			{ID: "denied", API: "d", Method: "GET", Target: "/d", Access: "deny", Auth: "none"},
		},
	}
	if withB {
		p.Operations = append(p.Operations, policy.Operation{ID: "read-b", API: "b", Method: "GET", Target: "/b/*", Access: "allow", Auth: "none"})
	}
	return p
}

// protectedPolicy is basePolicy(true) with authentication on every allowed
// operation and two roles.
func protectedPolicy() policy.Policy {
	p := basePolicy(true)
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

func permitOverride(kind, role, operation string, seconds int64) OverrideRequest {
	return OverrideRequest{Type: kind, Control: store.ControlPermit, Operation: operation, Role: new(role), ExpiresInSeconds: seconds}
}

func rateOverride(kind, operation string, count, seconds int64) OverrideRequest {
	return OverrideRequest{Type: kind, Control: store.ControlRate, Operation: operation, Count: new(count), ExpiresInSeconds: seconds}
}

func operationContainment(operation string, seconds int64) OverrideRequest {
	return OverrideRequest{Type: store.OverrideContainment, Control: store.ControlOperation, Operation: operation, ExpiresInSeconds: seconds}
}

func overrideErrorCode(err error) string {
	if policyErr, ok := errors.AsType[*policy.PolicyError](err); ok {
		return policyErr.Code + "@" + policyErr.Field
	}
	return fmt.Sprint(err)
}

func mustJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
