// A file system without space: the writer first releases the reserve file
// and writes again (reserve.go); without one, the log refuses admission,
// fail closed, and retries until a write and its sync succeed again. A
// failed sync, or any other write error, replaces the active file instead
// (recover.go): after a failed sync the kernel may have dropped the written
// pages, so a later success in the same file would not prove them durable.

package audit

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// spaceRetry is how often a log without file-system space retries a write:
// often enough that admission resumes within a second of space returning.
const spaceRetry = time.Second

// errNoSpace refuses a batch while the file system has no space for it.
var errNoSpace = fmt.Errorf("%w: no space left for the audit log", errAuditFailed)

// enterNoSpace records that the file system has no space: admission is
// refused, fail closed, until retrySpace writes again.
func (a *AuditLog) enterNoSpace(err error) {
	if !a.prefill {
		// An append may have left part of the batch past the logical end;
		// shrinking needs no space.
		if truncErr := a.file.Truncate(a.size); truncErr != nil {
			a.failWrite(errors.Join(err, truncErr), "sync_failed")
			return
		}
	}
	if a.noSpace.CompareAndSwap(false, true) {
		a.spaceSince = time.Now()
		slog.Error("audit log has no space; protected admission refused until space returns", "error", err)
	}
}

// retrySpace writes an audit.recovered record naming how long the log had no
// space; once it and its sync succeed, admission resumes. A retry that meets
// no space again leaves the outage and its start as they were.
func (a *AuditLog) retrySpace() {
	off := time.Since(a.spaceSince)
	e := Event{Kind: "audit.recovered", Reason: "storage_space", Lost: a.lost.Load(), DurationMS: float64(off) / float64(time.Millisecond)}
	// Waited for, so write counts it as nobody's loss if it fails again.
	if err := a.writeBatch([]*auditEntry{{event: a.stamp(e), done: make(chan error, 1)}}); err != nil {
		return
	}
	a.noSpace.Store(false)
	slog.Info("audit log has space again; protected admission resumed", "off", off.String())
}

// syncError marks an error of a sync rather than of a write.
type syncError struct{ err error }

func (e syncError) Error() string { return e.err.Error() }
func (e syncError) Unwrap() error { return e.err }

// spaceError reports whether err is a write refused for want of space, which
// a later write may pass; a failed sync is never one.
func spaceError(err error) bool {
	var failedSync syncError
	return !errors.As(err, &failedSync) && noSpace(err)
}
