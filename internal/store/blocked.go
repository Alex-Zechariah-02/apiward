// The blocked-accounts list and the control changes that edit it.

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/Alex-Zechariah-02/apiward/internal/fault"
	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

type BlockedAccount struct {
	Subject   string    `json:"subject"`
	Reason    string    `json:"reason"`
	BlockedBy string    `json:"blocked_by"`
	BlockedAt time.Time `json:"blocked_at"`
}

// BlockedAccounts is immutable after publication, independently of policy.
type BlockedAccounts map[string]BlockedAccount

const maxReason = 200

// SQLite bounds UTF-8 bytes because its TEXT length stops at NUL. Both HTTP
// input and durable state enforce the contract's Unicode character bound.
func ValidBlockReason(reason string) bool {
	count := utf8.RuneCountInString(reason)
	return utf8.ValidString(reason) && count >= 1 && count <= maxReason
}

// MaxBlockedAccounts bounds the published list, which is copied at every
// change and kept in memory; blocking more accounts is refused.
const MaxBlockedAccounts = 10000

// BlockedAccounts reads the list. One row past the bound is read, so an
// oversized table is refused without being read whole.
func (s *DB) BlockedAccounts(ctx context.Context) (BlockedAccounts, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject, reason, blocked_by, blocked_at FROM blocked_account LIMIT ?`, MaxBlockedAccounts+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := BlockedAccounts{}
	for rows.Next() {
		var entry BlockedAccount
		var at int64
		if err := rows.Scan(&entry.Subject, &entry.Reason, &entry.BlockedBy, &at); err != nil {
			return nil, err
		}
		if !policy.IsSubjectID(entry.Subject) || !IsAdminName(entry.BlockedBy) || !ValidBlockReason(entry.Reason) {
			return nil, errors.New("invalid blocked account")
		}
		entry.BlockedAt = time.UnixMilli(at).UTC()
		result[entry.Subject] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) > MaxBlockedAccounts {
		return nil, errors.New("too many blocked accounts")
	}
	return result, nil
}

// SaveBlockedAccount writes or replaces one blocked account in tx.
func SaveBlockedAccount(ctx context.Context, tx *sql.Tx, entry BlockedAccount) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO blocked_account (subject, reason, blocked_by, blocked_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(subject) DO UPDATE SET reason=excluded.reason, blocked_by=excluded.blocked_by, blocked_at=excluded.blocked_at`,
		entry.Subject, entry.Reason, entry.BlockedBy, entry.BlockedAt.UnixMilli())
	return err
}

// DeleteBlockedAccount removes one blocked account in tx.
func DeleteBlockedAccount(ctx context.Context, tx *sql.Tx, subject string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM blocked_account WHERE subject = ?`, subject)
	return err
}

// CommitControl keeps the state change, transition and exact replay response in
// the same SQLite transaction. The callback changes only controller-owned state.
func (s *DB) CommitControl(ctx context.Context, t TransitionRecord, body json.RawMessage, change func(*sql.Tx) error, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if change != nil {
		if err := change(tx); err != nil {
			return err
		}
	}
	fault.CrashPoint("commit-partway")
	if err := insertCommitted(ctx, tx, t, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO control_result (transition, body) VALUES (?, ?)`, t.ID, []byte(body)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *DB) ControlResult(ctx context.Context, id string) (json.RawMessage, error) {
	var result []byte
	err := s.db.QueryRowContext(ctx, `SELECT body FROM control_result WHERE transition = ?`, id).Scan(&result)
	return json.RawMessage(result), err
}
