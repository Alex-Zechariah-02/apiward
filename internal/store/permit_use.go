// Persistence of bounded-window permission use (permit_use and permit_use_window).

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// PermitUseRow is the last time one (role, operation) pair was admitted.
type PermitUseRow struct {
	Role      string
	Operation string
	LastUsed  time.Time
}

// PermitUseState is the persisted tracking window and per-pair last-used times.
type PermitUseState struct {
	Since    time.Time
	Requests int
	Used     []PermitUseRow
}

// LoadPermitUse reads the stored tracking window and all permit_use rows.
func (s *DB) LoadPermitUse(ctx context.Context) (PermitUseState, error) {
	var state PermitUseState
	var sinceMS int64
	err := s.db.QueryRowContext(ctx, `SELECT since, requests FROM permit_use_window WHERE id = 1`).Scan(&sinceMS, &state.Requests)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return PermitUseState{}, err
	}
	if err == nil && sinceMS > 0 {
		state.Since = time.UnixMilli(sinceMS).UTC()
	}
	rows, err := s.db.QueryContext(ctx, `SELECT role, operation, last_used FROM permit_use`)
	if err != nil {
		return PermitUseState{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var r PermitUseRow
		var lastMS int64
		if err := rows.Scan(&r.Role, &r.Operation, &lastMS); err != nil {
			return PermitUseState{}, err
		}
		r.LastUsed = time.UnixMilli(lastMS).UTC()
		state.Used = append(state.Used, r)
	}
	return state, rows.Err()
}

// ReplacePermitUse replaces permit_use and permit_use_window in one
// transaction, dropping any permit_use rows older than cutoff.
func (s *DB) ReplacePermitUse(ctx context.Context, state PermitUseState, cutoff time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM permit_use`); err != nil {
		return err
	}
	cutoffMS := cutoff.UnixMilli()
	for _, r := range state.Used {
		if r.LastUsed.UnixMilli() < cutoffMS {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO permit_use (role, operation, last_used) VALUES (?, ?, ?)`,
			r.Role, r.Operation, r.LastUsed.UnixMilli()); err != nil {
			return err
		}
	}
	if !state.Since.IsZero() {
		if _, err := tx.ExecContext(ctx, `INSERT INTO permit_use_window (id, since, requests) VALUES (1, ?, ?)
			ON CONFLICT(id) DO UPDATE SET since = excluded.since, requests = excluded.requests`,
			state.Since.UnixMilli(), state.Requests); err != nil {
			return err
		}
	}
	return tx.Commit()
}
