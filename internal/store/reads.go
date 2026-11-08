// The read-only view of the store that the Admin API is given.

package store

import (
	"context"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// Reads is every store read the Admin API makes. It has no write method, so
// code holding only Reads cannot change stored state; changes go through the
// controller.
type Reads interface {
	Load(ctx context.Context) (Authority, error)
	Policy(ctx context.Context, id int64) (policy.Policy, error)
	Revision(ctx context.Context, id int64) (RevisionInfo, bool, error)
	Revisions(ctx context.Context, after int64, limit int) ([]RevisionInfo, error)
	Candidate(ctx context.Context, id int64) (CandidateRecord, bool, error)
	Candidates(ctx context.Context, after int64, limit int) ([]CandidateRecord, error)
	Activation(ctx context.Context, column string, id int64) (ActivationRecord, bool, error)
	Activations(ctx context.Context, after int64, limit int) ([]ActivationRecord, error)
	Override(ctx context.Context, id int64) (Override, bool, error)
	Overrides(ctx context.Context, clause string, args ...any) ([]Override, error)
	History(ctx context.Context, filter HistoryFilter, after int64, limit int) ([]HistoryEntry, error)
	HistoryEntry(ctx context.Context, id string) (HistoryEntry, bool, error)
	Administrator(ctx context.Context, name string) (Administrator, bool, error)
	Administrators(ctx context.Context) ([]adminEntry, error)
	Enrolment(ctx context.Context, secretHash string) (Enrolment, bool, error)
}

var _ Reads = (*DB)(nil)
