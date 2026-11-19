// The database schema, one migration per schema version.

package store

// migrations holds the database schema, one entry per schema version. Install
// applies all of them; startup accepts only a database at the latest version
// whose schema is exactly what they create.
//
// The reasons for the fixed bounds are stated here, not in the SQL: a
// comment inside a statement would change the stored schema text and with it
// the fingerprint every existing database is checked against.
//   - deployment and base hold exactly one row (id = 1): two would be two
//     installation identities or two active policies.
//   - installation and recovery_episode are 32 hex characters, 128 random bits.
//   - A document is at most 65,536 bytes, the policy size ceiling; a stored
//     control answer has the same ceiling.
//   - A checksum is the 64 hex characters of SHA-256.
//   - An administrator name is 1 to 64 characters: it is part of transition
//     IDs and of every audit record about that administrator. Its character
//     set (IsAdminName) is checked in Go at every write and every read.
//   - permissions is a mask of the four permission bits, 1 to 15; 0 would be
//     an administrator with no right at all.
//   - A transition ID is 1 to 256 characters: the history key and the
//     idempotency key, built from bounded parts.
//   - At most one activation is unresolved: the base row has one provisional
//     revision and one deadline.
//   - Override operation and role names are 1 to 64 characters, the policy
//     identifier limit; a rate count is 1 to 1,000,000, so an override
//     cannot remove a limit altogether.
//   - A blocked subject is 1 to 128 characters and a reason 1 to 800 bytes;
//     a blocked range is 9 to 43 characters, the shortest IPv4 range to the
//     longest IPv6 one.
var migrations = []string{`
CREATE TABLE deployment (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	installation TEXT NOT NULL CHECK (length(installation) = 32),
	mode TEXT NOT NULL CHECK (mode IN ('bootstrap_locked', 'normal', 'recovery_required')),
	recovery_episode TEXT CHECK (recovery_episode IS NULL OR length(recovery_episode) = 32),
	high_water INTEGER NOT NULL,
	CHECK (mode <> 'recovery_required' OR recovery_episode IS NOT NULL)
) STRICT;
CREATE TABLE revision (
	id INTEGER PRIMARY KEY,
	parent INTEGER REFERENCES revision (id),
	origin TEXT NOT NULL CHECK (origin IN ('genesis', 'recovery_base', 'membership', 'publish')),
	document BLOB NOT NULL CHECK (length(document) BETWEEN 1 AND 65536),
	checksum TEXT NOT NULL CHECK (length(checksum) = 64),
	actor TEXT NOT NULL,
	created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE base (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	confirmed INTEGER REFERENCES revision (id),
	provisional INTEGER REFERENCES revision (id),
	deadline INTEGER,
	CHECK ((provisional IS NULL) = (deadline IS NULL)),
	CHECK (provisional IS NULL OR confirmed IS NOT NULL)
) STRICT;
CREATE TABLE candidate (
	id INTEGER PRIMARY KEY,
	parent INTEGER REFERENCES revision (id),
	document BLOB NOT NULL CHECK (length(document) BETWEEN 1 AND 65536),
	checksum TEXT NOT NULL CHECK (length(checksum) = 64),
	deny_all INTEGER NOT NULL CHECK (deny_all IN (0, 1)),
	status TEXT NOT NULL CHECK (status IN ('validated', 'withdrawn', 'established', 'quarantined')),
	actor TEXT NOT NULL,
	created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE administrator (
	name TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 64),
	permissions INTEGER NOT NULL CHECK (permissions BETWEEN 1 AND 15),
	password TEXT NOT NULL CHECK (password LIKE '$argon2id$%'),
	status TEXT NOT NULL CHECK (status IN ('active', 'quarantined')),
	credential INTEGER NOT NULL CHECK (credential >= 1),
	updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE enrolment (
	administrator TEXT PRIMARY KEY CHECK (length(administrator) BETWEEN 1 AND 64),
	secret TEXT NOT NULL UNIQUE CHECK (length(secret) = 64),
	permissions INTEGER NOT NULL CHECK (permissions BETWEEN 1 AND 15),
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE transition (
	id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 256),
	kind TEXT NOT NULL,
	actor TEXT NOT NULL,
	target TEXT NOT NULL,
	expected INTEGER,
	digest TEXT NOT NULL,
	outcome TEXT NOT NULL CHECK (outcome IN ('committed', 'rejected')),
	reason TEXT NOT NULL,
	result_revision INTEGER REFERENCES revision (id),
	result_candidate INTEGER REFERENCES candidate (id),
	committed_at INTEGER NOT NULL,
	published_at INTEGER,
	published_by TEXT,
	audited_at INTEGER,
	CHECK ((outcome = 'committed') = (reason = '')),
	CHECK (outcome = 'committed' OR (result_revision IS NULL AND result_candidate IS NULL AND published_at IS NULL))
) STRICT;
`, `
CREATE TABLE activation (
	revision INTEGER PRIMARY KEY REFERENCES revision (id),
	candidate INTEGER NOT NULL UNIQUE REFERENCES candidate (id),
	rollback_target INTEGER NOT NULL REFERENCES revision (id),
	deadline INTEGER NOT NULL,
	activated_at INTEGER NOT NULL,
	actor TEXT NOT NULL,
	disposition TEXT CHECK (disposition IN ('confirmed', 'rolled_back', 'timed_out', 'quarantined')),
	resolved_at INTEGER,
	resolved_by TEXT,
	resolution TEXT REFERENCES transition (id) DEFERRABLE INITIALLY DEFERRED,
	CHECK (rollback_target < revision),
	CHECK (deadline > activated_at),
	CHECK ((disposition IS NULL) = (resolved_at IS NULL)),
	CHECK ((disposition IS NULL) = (resolved_by IS NULL)),
	CHECK ((disposition IS NULL) = (resolution IS NULL))
) STRICT;
CREATE UNIQUE INDEX activation_unresolved ON activation ((disposition IS NULL)) WHERE disposition IS NULL;
CREATE TRIGGER activation_fixed BEFORE UPDATE OF revision, candidate, rollback_target, deadline, activated_at, actor ON activation
BEGIN SELECT RAISE(ABORT, 'an activation record cannot change'); END;
CREATE TRIGGER activation_final BEFORE UPDATE ON activation WHEN OLD.disposition IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'an activation has exactly one final disposition'); END;
CREATE TRIGGER activation_kept BEFORE DELETE ON activation
BEGIN SELECT RAISE(ABORT, 'activation history is kept'); END;
CREATE TRIGGER base_provisional BEFORE UPDATE ON base WHEN NEW.provisional IS NOT NULL AND NOT EXISTS (
	SELECT 1 FROM activation WHERE revision = NEW.provisional AND deadline = NEW.deadline
		AND rollback_target = NEW.confirmed AND disposition IS NULL)
BEGIN SELECT RAISE(ABORT, 'a provisional base needs its unresolved activation'); END;
`, `
CREATE TABLE override (
	id INTEGER PRIMARY KEY,
	type TEXT NOT NULL CHECK (type IN ('exception', 'containment')),
	control TEXT NOT NULL CHECK (control IN ('permit', 'rate', 'operation')),
	operation TEXT NOT NULL CHECK (length(operation) BETWEEN 1 AND 64),
	role TEXT CHECK (role IS NULL OR length(role) BETWEEN 1 AND 64),
	count INTEGER CHECK (count IS NULL OR count BETWEEN 1 AND 1000000),
	target TEXT NOT NULL,
	base INTEGER NOT NULL REFERENCES revision (id),
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	actor TEXT NOT NULL,
	creation TEXT NOT NULL UNIQUE REFERENCES transition (id) DEFERRABLE INITIALLY DEFERRED,
	status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired', 'quarantined')),
	resolved_at INTEGER,
	resolved_by TEXT,
	resolution TEXT UNIQUE REFERENCES transition (id) DEFERRABLE INITIALLY DEFERRED,
	CHECK ((control = 'permit') = (role IS NOT NULL)),
	CHECK ((control = 'rate') = (count IS NOT NULL)),
	CHECK (control <> 'operation' OR type = 'containment'),
	CHECK (target = control || ':' || CASE WHEN role IS NULL THEN '' ELSE role || ':' END || operation),
	CHECK (expires_at > created_at),
	CHECK ((status = 'active') = (resolved_at IS NULL)),
	CHECK ((status = 'active') = (resolved_by IS NULL)),
	CHECK ((status = 'active') = (resolution IS NULL))
) STRICT;
CREATE UNIQUE INDEX override_active_target ON override (target) WHERE status = 'active';
CREATE TRIGGER override_fixed BEFORE UPDATE OF id, type, control, operation, role, count, target, base, created_at, expires_at, actor, creation ON override
BEGIN SELECT RAISE(ABORT, 'an override cannot change'); END;
CREATE TRIGGER override_final BEFORE UPDATE ON override WHEN OLD.status <> 'active'
BEGIN SELECT RAISE(ABORT, 'an override has exactly one final disposition'); END;
CREATE TRIGGER override_kept BEFORE DELETE ON override
BEGIN SELECT RAISE(ABORT, 'override history is kept'); END;
`,
	// A historical restore quarantines every active override under its one
	// restore transition, which a UNIQUE resolution column refuses as soon as
	// two were active. SQLite cannot drop a column constraint, so the table is
	// rebuilt in the documented order (create, copy, drop, rename) with its
	// other definitions unchanged. Foreign key enforcement stays on: no table
	// references override, so dropping it affects no other row, and every row
	// is checked again as it is copied. Ordinary revocations and expiries stay
	// one transition per override; a resolution is otherwise shared only by
	// overrides quarantined together.
	`
CREATE TABLE new_override (
	id INTEGER PRIMARY KEY,
	type TEXT NOT NULL CHECK (type IN ('exception', 'containment')),
	control TEXT NOT NULL CHECK (control IN ('permit', 'rate', 'operation')),
	operation TEXT NOT NULL CHECK (length(operation) BETWEEN 1 AND 64),
	role TEXT CHECK (role IS NULL OR length(role) BETWEEN 1 AND 64),
	count INTEGER CHECK (count IS NULL OR count BETWEEN 1 AND 1000000),
	target TEXT NOT NULL,
	base INTEGER NOT NULL REFERENCES revision (id),
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	actor TEXT NOT NULL,
	creation TEXT NOT NULL UNIQUE REFERENCES transition (id) DEFERRABLE INITIALLY DEFERRED,
	status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired', 'quarantined')),
	resolved_at INTEGER,
	resolved_by TEXT,
	resolution TEXT REFERENCES transition (id) DEFERRABLE INITIALLY DEFERRED,
	CHECK ((control = 'permit') = (role IS NOT NULL)),
	CHECK ((control = 'rate') = (count IS NOT NULL)),
	CHECK (control <> 'operation' OR type = 'containment'),
	CHECK (target = control || ':' || CASE WHEN role IS NULL THEN '' ELSE role || ':' END || operation),
	CHECK (expires_at > created_at),
	CHECK ((status = 'active') = (resolved_at IS NULL)),
	CHECK ((status = 'active') = (resolved_by IS NULL)),
	CHECK ((status = 'active') = (resolution IS NULL))
) STRICT;
INSERT INTO new_override SELECT * FROM override;
DROP TABLE override;
ALTER TABLE new_override RENAME TO override;
CREATE UNIQUE INDEX override_active_target ON override (target) WHERE status = 'active';
CREATE UNIQUE INDEX override_resolution ON override (resolution) WHERE status IN ('revoked', 'expired');
CREATE TRIGGER override_fixed BEFORE UPDATE OF id, type, control, operation, role, count, target, base, created_at, expires_at, actor, creation ON override
BEGIN SELECT RAISE(ABORT, 'an override cannot change'); END;
CREATE TRIGGER override_final BEFORE UPDATE ON override WHEN OLD.status <> 'active'
BEGIN SELECT RAISE(ABORT, 'an override has exactly one final disposition'); END;
CREATE TRIGGER override_kept BEFORE DELETE ON override
BEGIN SELECT RAISE(ABORT, 'override history is kept'); END;
CREATE TRIGGER override_shared BEFORE UPDATE OF resolution ON override WHEN EXISTS (
	SELECT 1 FROM override WHERE resolution = NEW.resolution AND (status = 'quarantined') <> (NEW.status = 'quarantined'))
BEGIN SELECT RAISE(ABORT, 'a resolution is shared only by overrides quarantined together'); END;
`, `
CREATE TABLE blocked_account (
	subject TEXT PRIMARY KEY CHECK (length(subject) BETWEEN 1 AND 128),
	reason TEXT NOT NULL CHECK (length(CAST(reason AS BLOB)) BETWEEN 1 AND 800),
	blocked_by TEXT NOT NULL REFERENCES administrator (name),
	blocked_at INTEGER NOT NULL
) STRICT;
CREATE TABLE control_result (
	transition TEXT PRIMARY KEY REFERENCES transition (id),
	body BLOB NOT NULL CHECK (length(body) BETWEEN 1 AND 65536)
) STRICT;
`, `
CREATE TABLE blocked_address (
	cidr TEXT PRIMARY KEY CHECK (length(cidr) BETWEEN 9 AND 43),
	reason TEXT NOT NULL CHECK (length(CAST(reason AS BLOB)) BETWEEN 1 AND 800),
	blocked_by TEXT NOT NULL REFERENCES administrator (name),
	blocked_at INTEGER NOT NULL,
	expires_at INTEGER CHECK (expires_at IS NULL OR expires_at > blocked_at)
) STRICT;
`,
	// History is pruned when a revision is committed (prune.go), so deletes
	// are no longer refused outright: only a row still in use is kept. What
	// such a row references is kept by the foreign keys.
	`
DROP TRIGGER activation_kept;
DROP TRIGGER override_kept;
CREATE TRIGGER activation_kept BEFORE DELETE ON activation WHEN OLD.disposition IS NULL
BEGIN SELECT RAISE(ABORT, 'an unresolved activation is kept'); END;
CREATE TRIGGER override_kept BEFORE DELETE ON override WHEN OLD.status = 'active'
BEGIN SELECT RAISE(ABORT, 'an active override is kept'); END;
CREATE TRIGGER revision_kept BEFORE DELETE ON revision WHEN
	EXISTS (SELECT 1 FROM base WHERE confirmed = OLD.id OR provisional = OLD.id)
	OR EXISTS (SELECT 1 FROM activation WHERE disposition IS NULL AND rollback_target = OLD.id)
	OR EXISTS (SELECT 1 FROM override WHERE status = 'active' AND base = OLD.id)
BEGIN SELECT RAISE(ABORT, 'a revision in use is kept'); END;
CREATE TRIGGER transition_kept BEFORE DELETE ON transition WHEN OLD.outcome = 'committed' AND OLD.audited_at IS NULL
BEGIN SELECT RAISE(ABORT, 'a transition without its audit record is kept'); END;
`,
	// Control changes prune the oldest control transitions (prune.go), which
	// they find by commit time.
	`
CREATE INDEX transition_committed ON transition (committed_at);
`}

// DatabaseVersion is the schema version this build reads and writes: the
// number of migrations, which a test checks.
const DatabaseVersion = 8
