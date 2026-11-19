// Audit storage capacity: the byte budget of every file, writing again once
// rotated files are moved away, and the optional eviction of the oldest.

package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
)

// What the log does when every file is in use: refuse every record (and so
// every admission) until an operator moves rotated files away, or delete the
// oldest rotated file after recording what it held.
const (
	FullRefuse = "refuse"
	FullEvict  = "evict_oldest"
)

var errFull = errors.New("audit storage full")

// rotatedSet describes the rotated files of the active file.
type rotatedSet struct {
	count  int
	oldest string // the oldest file's path, "" when there is none
	bytes  int64  // their total size
}

// rotatedFiles finds the rotated files of path.
func rotatedFiles(path string) (rotatedSet, error) {
	files, err := RotatedFiles(path)
	if err != nil || len(files) == 0 {
		return rotatedSet{}, err
	}
	set := rotatedSet{count: len(files), oldest: filepath.Join(filepath.Dir(path), files[0].Name)}
	for _, file := range files {
		set.bytes += file.Bytes
	}
	return set, nil
}

// makeRoom frees a rotated slot before a rotation. It counts the rotated
// files again first, so files an operator moved away free their slots
// without a restart. With nothing freed it evicts the oldest file when the
// log may, else it fails with errFull and the caller refuses the batch.
func (a *AuditLog) makeRoom() error {
	set, err := rotatedFiles(a.path)
	if err != nil {
		return err
	}
	a.rotated, a.rotatedBytes = set.count, set.bytes
	if a.rotated < a.maxFiles-1 {
		return nil
	}
	if !a.evict {
		return fmt.Errorf("%w: %d files of up to %d bytes exist; move rotated files to an archive and writing resumes", errFull, a.maxFiles, a.maxBytes)
	}
	return a.evictOldest(set.oldest)
}

// evictOldest deletes the rotated file name only after a record naming it,
// with its size, digest and the times of its first and last records, is
// synced in the active file; a crash between the two leaves the record and
// the file, never a deletion without its record.
func (a *AuditLog) evictOldest(name string) error {
	summary, err := a.described(name)
	if err != nil {
		return err
	}
	summary.File = filepath.Base(name)
	record, head := a.chain(a.appendEvent(nil, a.stamp(summary)), a.head)
	if err := a.persist(record); err != nil {
		return err
	}
	a.head = head
	if err := os.Remove(name); err != nil {
		return err
	}
	if err := filecheck.SyncDir(filepath.Dir(name)); err != nil {
		return err
	}
	a.rotated--
	a.rotatedBytes -= summary.Bytes
	a.evictions.Add(1)
	return nil
}

// Losses is how many refused records the log has counted in its loss
// records since the start; Evictions how many files it deleted when full.
func (a *AuditLog) Losses() uint64    { return a.lossTotal.Load() }
func (a *AuditLog) Evictions() uint64 { return a.evictions.Load() }

// describe reads a rotated file once: its size, SHA-256 and the times of its
// first and last records, as an audit.evicted event.
func describe(name string) (Event, error) {
	file, err := os.Open(name)
	if err != nil {
		return Event{}, err
	}
	defer file.Close()
	sum := sha256.New()
	reader := bufio.NewReaderSize(io.TeeReader(file, sum), MaxRecordBytes)
	e := Event{Kind: "audit.evicted"}
	for {
		line, err := reader.ReadSlice('\n')
		e.Bytes += int64(len(line))
		if len(line) > 0 && err == nil {
			var record struct {
				Time time.Time `json:"time"`
			}
			if json.Unmarshal(line, &record) == nil {
				if e.First.IsZero() {
					e.First = record.Time
				}
				e.Last = record.Time
			}
		}
		if err == io.EOF {
			break
		}
		// A line longer than the buffer is no record; its bytes still count.
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return Event{}, err
		}
	}
	e.Digest = hex.EncodeToString(sum.Sum(nil))
	return e, nil
}

// markFull records that every file is in use. The log keeps its file and
// retries at each later rotation, so it is not failed.
func (a *AuditLog) markFull(err error) {
	if a.full.CompareAndSwap(false, true) {
		slog.Error("audit log full; protected admission refused until rotated files are moved away", "error", err)
	}
}

// Budget reports the bytes held by every audit file and the budget, files ×
// file size, as last stored by the writer.
func (a *AuditLog) Budget() (used, total int64) {
	return a.usedBytes.Load(), a.maxBytes * int64(a.maxFiles)
}

// Evicts reports whether the log deletes its oldest file when full.
func (a *AuditLog) Evicts() bool { return a.evict }
