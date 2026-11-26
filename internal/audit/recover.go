// Replacing the active file after a failed sync, write or rotation, without
// a restart. After a failed sync the kernel may have dropped the pages
// written since the last good one, and Linux reports a writeback error only
// once per open file, so nothing later written to that file proves durable
// (PostgreSQL stops and replays its log for this reason). The writer
// therefore closes the suspect file, keeps it as a rotated file, opens a new
// active file under a new run ID (as a restart does, so verification counts
// the suspect file's unsynced tail as unchained, not altered) and writes
// audit.recovered naming the suspect file and the end of its last synced
// batch. Admission is refused only until that record is synced; while the
// replacement fails the writer tries again every spaceRetry.

package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
)

// errDown refuses a batch while the active file is being replaced; like a
// batch refused for want of space, its events leave the accepted count and
// those nobody waits for are counted as lost.
var errDown = fmt.Errorf("%w: the audit file is being replaced", errAuditFailed)

// failWrite refuses the batch whose write failed with err and replaces the
// active file. A failure while the log is already down only leaves it down,
// so a replacement never recurses.
func (a *AuditLog) failWrite(err error, reason string) error {
	if a.down.Load() {
		return errDown
	}
	a.down.Store(true)
	a.noSpace.Store(false)
	a.downSince, a.downReason = time.Now(), reason
	a.suspect, a.suspectEnd = filepath.Base(a.path), a.size
	slog.Error("audit file failed; replacing it, protected admission refused until the new file is written", "reason", reason, "error", err)
	// A disk that keeps failing gets a new file once per spaceRetry, not
	// one per failed batch.
	if time.Since(a.replaced) >= spaceRetry {
		a.replace()
	}
	return errDown
}

// replace opens a new active file and writes audit.recovered; on failure
// the log stays down and the writer calls it again.
func (a *AuditLog) replace() {
	a.replaced = time.Now()
	if err := a.reopen(); err != nil {
		slog.Error("audit file not replaced yet; retrying", "error", err)
		return
	}
	e := Event{Kind: "audit.recovered", Reason: a.downReason, File: a.suspect, Offset: a.suspectEnd, Lost: a.lost.Load(),
		DurationMS: float64(time.Since(a.downSince)) / float64(time.Millisecond)}
	// Waited for, so write counts it as nobody's loss if it fails again.
	if err := a.writeBatch([]*auditEntry{{event: a.stamp(e), done: make(chan error, 1)}}); err != nil {
		return
	}
	a.down.Store(false)
	a.recoveries.Add(1)
	slog.Info("audit file replaced; protected admission resumed", "suspect", a.suspect, "synced_end", a.suspectEnd)
}

// reopen closes the active file and moves it aside: a file this recovery
// opened that holds no synced record is deleted, any other is renamed as a
// rotated file, the one the next file's marker names. It then opens a new
// active file under a new run ID with an empty chain.
func (a *AuditLog) reopen() error {
	if a.file != nil {
		// The file is already suspect; its close error adds nothing.
		_ = a.file.Close()
		a.file = nil
	}
	if err := a.setAside(); err != nil {
		return err
	}
	// 0600 keeps a new audit file readable and writable only by the gateway's user.
	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	a.file, a.size, a.filled, a.fresh = file, 0, 0, true
	if err := filecheck.SyncDir(filepath.Dir(a.path)); err != nil {
		return err
	}
	a.boot = NewRequestID()[:16]
	clear(a.head[:])
	a.publishUsage()
	a.archive.signal()
	return nil
}

// setAside removes or renames the file at the active path, if any.
func (a *AuditLog) setAside() error {
	info, err := os.Lstat(a.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if a.fresh {
		return errors.Join(os.Remove(a.path), filecheck.SyncDir(filepath.Dir(a.path)))
	}
	rotated, err := a.freeName(time.Now())
	if err != nil {
		return err
	}
	if err := os.Rename(a.path, rotated); err != nil {
		return err
	}
	a.suspect, a.marker = filepath.Base(rotated), filepath.Base(rotated)
	a.rotated++
	a.rotatedBytes += info.Size()
	return nil
}
