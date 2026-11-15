// History pruning: what a commit deletes, what it keeps, and the triggers
// that refuse to delete a row in use.

package gateway

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// A database migrated from the previous schema version keeps exactly the
// newest revisions it is asked to keep. Committing a revision deletes the
// older ones with their trials, finished overrides, drafts and audited
// transitions, and never a row in use: the confirmed base, an active
// override, a transition whose audit record is missing, or what they name.
func TestHistoryPruning(t *testing.T) {
	t.Parallel()
	e := gatewaytest.NewEnv(t)
	gatewaytest.Seed(t, e.Database, e.ProtectedPolicy(), gatewaytest.SeedOptions{Version: store.DatabaseVersion - 1})
	ctx := t.Context()
	start := time.Now()
	old, from, err := store.OpenForMigration(e.Database)
	if err != nil {
		t.Fatal(err)
	}
	record := func(id, kind string) store.TransitionRecord {
		return store.TransitionRecord{ID: id, Kind: kind, Actor: gatewaytest.HarnessAdmin, Target: "t", Digest: "d"}
	}
	if err := old.Migrate(ctx, from, record("migrate", "operator.migrate"), start); err != nil {
		t.Fatalf("migrating from version %d: %v", from, err)
	}
	old.Close()

	db, err := store.Connect(e.Database, "WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Verify(db); err != nil {
		t.Fatalf("the migrated database: %v", err)
	}
	s := store.Adopt(db)
	document, _ := json.Marshal(e.ProtectedPolicy())
	const keep = 3
	tick := 0
	now := func() time.Time {
		tick++
		return start.Add(time.Duration(tick) * time.Second)
	}
	audited := func(id string) {
		t.Helper()
		if err := s.MarkAudited(ctx, id, now()); err != nil {
			t.Fatal(err)
		}
	}
	// publish commits a revision on parent: confirmed at once, or on trial
	// from candidate until a deadline.
	publish := func(parent, candidate int64) int64 {
		t.Helper()
		change := store.RevisionChange{Parent: parent, Origin: "publish", Document: document, Actor: gatewaytest.HarnessAdmin, Mode: store.ModeNormal, Candidate: candidate, Keep: keep}
		at := now()
		if candidate != 0 {
			change.Deadline = at.Add(time.Hour)
		}
		id := fmt.Sprintf("publish-%d", tick)
		revision, err := s.CommitRevision(ctx, record(id, "policy.publish"), change, at)
		if err != nil {
			t.Fatalf("committing on revision %d: %v", parent, err)
		}
		audited(id)
		return revision
	}
	// Read on the store's own connection: it holds the database.
	expect := func(what, query string, want ...string) {
		t.Helper()
		rows, err := db.Query(query)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		defer rows.Close()
		got := []string{}
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				t.Fatalf("%s: %v", what, err)
			}
			got = append(got, value)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: %v, want %v", what, got, want)
		}
	}

	audited("migrate")
	head := int64(1)
	for range 4 {
		head = publish(head, 0)
	}
	expect("revisions after five commits", `SELECT id FROM revision ORDER BY id`, "3", "4", "5")
	expect("the oldest kept revision's parent", `SELECT COUNT(*) FROM revision WHERE id = 3 AND parent IS NULL`, "1")
	expect("transitions of deleted revisions", `SELECT COUNT(*) FROM transition WHERE result_revision < 3 OR id = 'migrate'`, "0")
	expect("transitions of kept revisions", `SELECT COUNT(*) FROM transition`, "3")

	// Revision 5 stays the confirmed base while four trials on it are undone:
	// it and the active override on it are older than the newest three.
	override := func(id int64, operation string) {
		t.Helper()
		at := now()
		o := store.Override{ID: id, Type: store.OverrideContainment, Control: store.ControlOperation, Operation: operation, Target: store.ControlOperation + ":" + operation,
			Base: 5, CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour), Actor: gatewaytest.HarnessAdmin}
		if err := s.CommitOverride(ctx, record(fmt.Sprintf("create-%d", id), "tpo.create"), o, at); err != nil {
			t.Fatal(err)
		}
		audited(fmt.Sprintf("create-%d", id))
	}
	override(1, "read-a")
	override(2, "read-b")
	if err := s.CommitOverrideEnd(ctx, record("revoke-1", "tpo.revoke"), 1, store.OverrideRevoked, now()); err != nil {
		t.Fatal(err)
	}
	audited("revoke-1")
	for trial := range 4 {
		at := now()
		draft := fmt.Sprintf("draft-%d", trial)
		candidate, err := s.CommitCandidate(ctx, record(draft, "candidate.create"), store.CandidateRecord{Parent: 5, Document: document, Checksum: store.DocumentChecksum(document), Actor: gatewaytest.HarnessAdmin}, at)
		if err != nil {
			t.Fatal(err)
		}
		audited(draft)
		provisional := publish(5, candidate)
		if trial == 3 {
			break
		}
		undo := fmt.Sprintf("undo-%d", trial)
		if err := s.CommitResolution(ctx, record(undo, "cpa.rollback"), store.Authority{Confirmed: 5, Provisional: provisional}, store.DispositionRolledBack, now()); err != nil {
			t.Fatal(err)
		}
		// The first undo's audit record is never written.
		if trial > 0 {
			audited(undo)
		}
	}
	expect("revisions with the base older than the newest three", `SELECT id FROM revision ORDER BY id`, "5", "7", "8", "9")
	expect("overrides", `SELECT id FROM override ORDER BY id`, "2")
	expect("activations", `SELECT revision FROM activation ORDER BY revision`, "7", "8", "9")
	expect("the transition without its audit record", `SELECT COUNT(*) FROM transition WHERE id = 'undo-0'`, "1")
	expect("transitions of the deleted override", `SELECT COUNT(*) FROM transition WHERE id IN ('create-1', 'revoke-1')`, "0")
	expect("foreign keys", `SELECT COUNT(*) FROM pragma_foreign_key_check`, "0")

	if _, err := db.Exec(`INSERT INTO transition (id, kind, actor, target, digest, outcome, reason, committed_at) VALUES ('rejected', 'k', 'a', 't', 'd', 'rejected', 'STALE', 0)`); err != nil {
		t.Fatal(err)
	}
	refusals := []struct{ name, query, failure string }{
		{"the confirmed base", `DELETE FROM revision WHERE id = 5`, "a revision in use is kept"},
		{"the provisional base", `DELETE FROM revision WHERE id = 9`, "a revision in use is kept"},
		{"the unresolved activation", `DELETE FROM activation WHERE revision = 9`, "an unresolved activation is kept"},
		{"the active override", `DELETE FROM override WHERE id = 2`, "an active override is kept"},
		{"a transition without its audit record", `DELETE FROM transition WHERE id = 'undo-0'`, "a transition without its audit record is kept"},
	}
	for _, r := range refusals {
		if _, err := db.Exec(r.query); err == nil || !strings.Contains(err.Error(), r.failure) {
			t.Errorf("deleting %s: %v, want %q", r.name, err, r.failure)
		}
	}
	if _, err := db.Exec(`DELETE FROM transition WHERE id = 'rejected'`); err != nil {
		t.Errorf("deleting a rejected transition: %v", err)
	}
}
