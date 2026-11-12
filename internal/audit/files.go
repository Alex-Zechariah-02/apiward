// Audit file opening, recovery and rotation.

package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/fault"
)

// Default size of the active audit file and number of files kept.
const (
	DefaultAuditBytes = 64 << 20
	DefaultAuditFiles = 8
)

// Settings bound the log: the size of each file, how many files it keeps,
// what it does when all are in use (FullRefuse or FullEvict), how many
// records its queue holds (QueueSize), its sync window (0: none) and
// whether it appends to the active file (Append) instead of zero-filling it
// ahead of the writer on Linux; copy-on-write file systems gain nothing from
// the fill.
type Settings struct {
	MaxBytes int64
	MaxFiles int
	WhenFull string
	Queue    int
	Window   time.Duration
	Append   bool
}

// OpenAudit never fails: an unusable file yields a log in the failed state,
// which refuses every acknowledgement and therefore every admission.
func OpenAudit(path string, s Settings) *AuditLog {
	a := &AuditLog{
		boot:     NewRequestID()[:16],
		path:     path,
		maxBytes: s.MaxBytes,
		maxFiles: s.MaxFiles,
		evict:    s.WhenFull == FullEvict,
		window:   s.Window,
		prefill:  prefillSupported && !s.Append,
		queue:    make(chan auditEntry, max(s.Queue, AuditQueueSize)),
		done:     make(chan struct{}),
	}
	incomplete, err := a.open()
	if err != nil {
		if a.file != nil {
			a.file.Close()
			a.file = nil
		}
		a.openErr = err
		a.Fail(fmt.Errorf("opening audit log: %w", err))
		close(a.done)
		return a
	}
	if incomplete >= 0 {
		// A crash interrupted the last record. It stays in the file for
		// inspection; this event names where it starts.
		a.Record(Event{Kind: "audit.recovered", File: filepath.Base(path), Offset: incomplete})
	}
	go a.run()
	return a
}

// open checks and opens the active file and finds the rotated files. It
// truncates the file to its logical end (End), removing the zero tail a
// crash left. A non-empty file whose content does not end with a newline
// holds an incomplete record from a crash: open terminates it with a newline,
// so the next record starts on its own line, and returns its offset, or -1
// when the file is complete.
func (a *AuditLog) open() (int64, error) {
	info, err := os.Lstat(a.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return -1, err
	case !info.Mode().IsRegular():
		return -1, fmt.Errorf("%s is not a regular file", a.path)
	}

	set, err := rotatedFiles(a.path)
	if err != nil {
		return -1, err
	}
	a.rotated, a.next, a.rotatedBytes = set.count, set.next, set.bytes
	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return -1, err
	}
	a.file = file
	end, err := End(file)
	if err != nil {
		return -1, err
	}
	incomplete, err := incompleteRecord(file, end)
	if err != nil {
		return -1, err
	}
	if err := a.trim(end); err != nil {
		return -1, err
	}
	a.size, a.filled = end, end
	if incomplete >= 0 {
		if err := a.persist([]byte("\n")); err != nil {
			return -1, err
		}
	}
	a.publishUsage()
	return incomplete, nil
}

// incompleteRecord returns the offset of an unterminated last record of the
// file's content, which ends at end, or -1.
func incompleteRecord(file *os.File, end int64) (int64, error) {
	if end == 0 {
		return -1, nil
	}
	start := max(end-MaxRecordBytes, 0)
	tail := make([]byte, end-start)
	if _, err := file.ReadAt(tail, start); err != nil && err != io.EOF {
		return -1, err
	}
	if tail[len(tail)-1] == '\n' {
		return -1, nil
	}
	return start + int64(bytes.LastIndexByte(tail, '\n')+1), nil
}

// rotate trims the active file to its logical end, closes it, renames it to
// the next rotated name and opens a new active file; makeRoom has freed a
// slot for it. Every batch was synced when written, so closing loses nothing,
// and the trim is synced before the rename, so a rotated file never carries
// a zero tail.
func (a *AuditLog) rotate() (string, error) {
	closed := a.size
	if err := a.trim(closed); err != nil {
		return "", err
	}
	err := a.file.Close()
	a.file = nil
	if err != nil {
		return "", err
	}
	rotated := fmt.Sprintf("%s.%d", a.path, a.next)
	if err := os.Rename(a.path, rotated); err != nil {
		return "", err
	}
	fault.CrashPoint("audit-after-rename")
	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	a.file, a.size, a.filled = file, 0, 0
	a.rotated++
	a.rotatedBytes += closed
	a.next++
	a.publishUsage()
	return filepath.Base(rotated), nil
}

// Usage reports the active file's size and the number of files, each with
// its limit, as last stored by the writer.
func (a *AuditLog) Usage() (activeBytes, activeLimit, files, filesLimit int64) {
	return a.activeBytes.Load(), a.maxBytes, a.files.Load(), int64(a.maxFiles)
}

// Failed reports whether the log refuses new records: it has failed, or
// every file is in use.
func (a *AuditLog) Failed() bool { return a.failed.Load() || a.full.Load() }

// OpenErr is why the log could not open its file, or nil.
func (a *AuditLog) OpenErr() error { return a.openErr }

// Path is the active audit file's path.
func (a *AuditLog) Path() string { return a.path }

// Lost is the number of refused events not yet counted in the file.
func (a *AuditLog) Lost() uint64 { return a.lost.Load() }

// Closed reports whether the writer has ended; it closes its file first.
func (a *AuditLog) Closed() bool {
	select {
	case <-a.done:
		return true
	default:
		return false
	}
}
