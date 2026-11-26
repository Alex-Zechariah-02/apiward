// Audit storage capacity: the bound on the active folder, which only the
// opt-in FullRefuse enforces by refusing records; under FullEvict the
// archiver (archive.go) keeps the folder within it by evicting.

package audit

import (
	"errors"
	"fmt"
	"log/slog"
)

// What the log does when its storage is full: refuse every record (and so
// every admission) until files are moved away, or delete the oldest file
// after recording what it held (the default).
const (
	FullRefuse = "refuse"
	FullEvict  = "evict_oldest"
)

var errFull = errors.New("audit storage full")

// rotatedSet describes the rotated files in the active file's folder: their
// total size on disk, and the room they take, each at most one file's size
// (a batch may finish a file past it).
type rotatedSet struct {
	count int
	bytes int64
	room  int64
}

// rotatedFiles finds the rotated files in path's folder; each takes at most
// limit of room.
func rotatedFiles(path string, limit int64) (rotatedSet, error) {
	files, err := RotatedFiles(path, "")
	if err != nil {
		return rotatedSet{}, err
	}
	set := rotatedSet{count: len(files)}
	for _, file := range files {
		set.bytes += file.Bytes
		set.room += min(file.Bytes, limit)
	}
	return set, nil
}

// makeRoom checks, before a rotation, that the active folder has room for
// another file: its rotated files' room plus two files' (the file being
// closed and a new one) within maxFiles × maxBytes; for uncompressed files
// this is "fewer than maxFiles-1 rotated files", and compressed files take
// their size. It counts the files again first, so files
// moved away free room without a restart. Under FullEvict it never refuses;
// the archiver keeps the folder within the bound.
func (a *AuditLog) makeRoom() error {
	set, err := rotatedFiles(a.path, a.maxBytes)
	if err != nil {
		return err
	}
	a.rotated, a.rotatedBytes = set.count, set.bytes
	if a.evict || set.room+2*a.maxBytes <= a.budget() {
		return nil
	}
	return fmt.Errorf("%w: rotated files take %d of %d bytes, leaving no room for another file; move rotated files away and writing resumes", errFull, set.room, a.budget())
}

// budget is the active folder's bound, files × file size.
func (a *AuditLog) budget() int64 { return a.maxBytes * int64(a.maxFiles) }

// Losses is how many refused records the log has counted in its loss
// records since the start; Evictions how many files it deleted; Recoveries
// how many active files it replaced after a failed sync or write.
func (a *AuditLog) Losses() uint64    { return a.lossTotal.Load() }
func (a *AuditLog) Evictions() uint64 { return a.evictions.Load() }
func (a *AuditLog) Recoveries() int64 { return a.recoveries.Load() }

// markFull records that the active folder is at its bound. The log keeps its
// file and retries at each later rotation, so it is not failed.
func (a *AuditLog) markFull(err error) {
	if a.moveHealth(healthWriting, healthFull) {
		slog.Error("audit log full; protected admission refused until rotated files are moved away (gateway.audit_when_full is \"refuse\")", "error", err)
	}
}

// Budget reports the bytes held in the active folder and its bound, as last
// stored by the writer.
func (a *AuditLog) Budget() (used, total int64) {
	return a.usedBytes.Load(), a.budget()
}

// Evicts reports whether the oldest files are deleted, recorded first.
func (a *AuditLog) Evicts() bool { return a.evict }
