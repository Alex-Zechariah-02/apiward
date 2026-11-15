// Pruning of the history tables: when a revision is committed, the rows only
// older revisions need are deleted in the same transaction, so the database
// stops growing with every change. The audit log files stay the full record.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// spareRevision holds for a revision r that no remaining row needs: not a
// base, not named by an activation or an override, not the result of a kept
// transition. Parent links are cleared before the delete, so they do not count.
const spareRevision = `
	NOT EXISTS (SELECT 1 FROM base WHERE confirmed = r.id OR provisional = r.id)
	AND NOT EXISTS (SELECT 1 FROM activation AS a WHERE a.revision = r.id OR a.rollback_target = r.id)
	AND NOT EXISTS (SELECT 1 FROM override AS o WHERE o.base = r.id)
	AND NOT EXISTS (SELECT 1 FROM transition AS t WHERE t.result_revision = r.id)`

// spareTransition holds for a transition from before the oldest kept
// revision (?1; ?2 is when that revision was created) whose audit record is
// written and that no kept activation or override names. A rejected
// transition has no audit receipt to wait for.
const spareTransition = `
	(result_revision < ?1 OR result_revision IS NULL AND committed_at < ?2)
	AND (outcome = 'rejected' OR audited_at IS NOT NULL)
	AND id NOT IN (SELECT resolution FROM activation WHERE resolution IS NOT NULL)
	AND id NOT IN (SELECT creation FROM override)
	AND id NOT IN (SELECT resolution FROM override WHERE resolution IS NOT NULL)`

// pruning runs oldest reference first, so no delete meets a row that still
// points at what it removes. The newest override and candidate always stay:
// their tables number new rows from the highest ID present, and an ID is
// never given out twice. byTime marks the steps that also take ?2.
var pruning = []struct {
	query  string
	byTime bool
}{
	{`DELETE FROM activation WHERE disposition IS NOT NULL AND revision < ?1`, false},
	{`DELETE FROM override WHERE status <> 'active' AND base < ?1 AND id < (SELECT max(id) FROM override)`, false},
	{`DELETE FROM control_result WHERE transition IN (SELECT id FROM transition WHERE` + spareTransition + `)`, true},
	{`DELETE FROM transition WHERE` + spareTransition, true},
	{`DELETE FROM candidate WHERE parent < ?1 AND id < (SELECT max(id) FROM candidate)
		AND NOT EXISTS (SELECT 1 FROM activation AS a WHERE a.candidate = candidate.id)
		AND NOT EXISTS (SELECT 1 FROM transition AS t WHERE t.result_candidate = candidate.id)`, false},
	{`UPDATE candidate SET parent = NULL WHERE parent IN (SELECT r.id FROM revision AS r WHERE r.id < ?1 AND` + spareRevision + `)`, false},
	{`UPDATE revision SET parent = NULL WHERE parent IN (SELECT r.id FROM revision AS r WHERE r.id < ?1 AND` + spareRevision + `)`, false},
	{`DELETE FROM revision AS r WHERE r.id < ?1 AND` + spareRevision, false},
}

// prune keeps the newest keep revisions and deletes what only older ones
// need; keep 0 deletes nothing. A row in use (the schema's *_kept triggers
// name them) is never deleted, nor anything it references.
func prune(ctx context.Context, tx *sql.Tx, keep int) error {
	if keep <= 0 {
		return nil
	}
	var oldest, created int64
	err := tx.QueryRowContext(ctx, `SELECT id, created_at FROM revision ORDER BY id DESC LIMIT 1 OFFSET ?`, keep-1).Scan(&oldest, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pruning history: %w", err)
	}
	for _, step := range pruning {
		args := []any{oldest}
		if step.byTime {
			args = append(args, created)
		}
		if _, err := tx.ExecContext(ctx, step.query, args...); err != nil {
			return fmt.Errorf("pruning history: %w", err)
		}
	}
	return nil
}

// MaxUnused is how many unused candidates (staged or withdrawn, never
// activated) the database keeps: at the 64 KiB policy ceiling about
// 6.4 MiB. Staging past it deletes the oldest, so repeated staging cannot
// fill the disk the audit log shares.
const MaxUnused = 100

// unusedCandidate holds for a candidate c no activation names whose staging
// and withdrawal records are durably audited.
const unusedCandidate = `c.status IN ('validated', 'withdrawn')
	AND NOT EXISTS (SELECT 1 FROM activation AS a WHERE a.candidate = c.id)
	AND NOT EXISTS (SELECT 1 FROM transition AS t WHERE t.result_candidate = c.id AND t.audited_at IS NULL)`

// trimming deletes the oldest unused candidates past ?1 to keep, with the
// transitions that produced them, child rows first.
var trimming = []string{
	`DELETE FROM control_result WHERE transition IN (SELECT id FROM transition WHERE result_candidate IN
		(SELECT c.id FROM candidate AS c WHERE ` + unusedCandidate + ` ORDER BY c.id LIMIT ?1))`,
	`DELETE FROM transition WHERE result_candidate IN
		(SELECT c.id FROM candidate AS c WHERE ` + unusedCandidate + ` ORDER BY c.id LIMIT ?1)`,
	`DELETE FROM candidate WHERE id IN
		(SELECT c.id FROM candidate AS c WHERE ` + unusedCandidate + ` ORDER BY c.id LIMIT ?1)`,
}

// trimCandidates makes room for one more candidate: when MaxUnused unused
// candidates exist, it deletes the oldest so MaxUnused-1 remain.
func trimCandidates(ctx context.Context, tx *sql.Tx) error {
	var unused int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM candidate AS c WHERE `+unusedCandidate).Scan(&unused); err != nil {
		return fmt.Errorf("trimming candidates: %w", err)
	}
	excess := unused - (MaxUnused - 1)
	if excess <= 0 {
		return nil
	}
	for _, query := range trimming {
		if _, err := tx.ExecContext(ctx, query, excess); err != nil {
			return fmt.Errorf("trimming candidates: %w", err)
		}
	}
	return nil
}
