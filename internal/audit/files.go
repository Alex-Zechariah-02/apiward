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
	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
)

// Default size of the active audit file and the number of such files that
// bound the log folder (active plus rotated files not yet archived).
const (
	DefaultAuditBytes = 64 << 20
	DefaultAuditFiles = 8
)

// MaxAuditBytes is the largest file size gateway.audit_max_bytes accepts, and
// so the largest uncompressed size a compressed file's header may state.
const MaxAuditBytes = 1 << 30

// Settings bound the log: the size of each file, how many files the log
// folder holds, what it does when its storage is full (FullRefuse or
// FullEvict), how many
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
	// Privacy is how client addresses are recorded; the zero value records
	// them whole.
	Privacy Privacy
	// OutcomeWindow is the longest a request can live; after an unclean
	// stop, admissions this close to the last record without an outcome
	// are marked unknown (reconcile.go). 0 skips the check.
	OutcomeWindow time.Duration
	// Signer signs the chain's checkpoints; nil writes none.
	Signer Signer
	Storage
}

// Storage is where rotated files go and how the log keeps its disks from
// filling. Archive is the folder rotated files move to; "" runs no
// archiver, so rotated files stay where they are and nothing is evicted
// (operator commands, which run while the gateway is stopped).
// ArchiveBytes bounds the archive folder (0: no bound); Plain moves rotated
// files uncompressed; MinFree is the free share of a disk, in percent,
// below which the oldest files are evicted early (0: never); Reserve is the
// size of the reserve file (0: none).
type Storage struct {
	Archive      string
	ArchiveBytes int64
	Plain        bool
	MinFree      int
	Reserve      int64
}

type auditConfig struct {
	reservePause time.Duration
	opener       func(string, int, os.FileMode) (*os.File, error)
}

type auditOption func(*auditConfig)

func withReservePause(d time.Duration) auditOption {
	return func(c *auditConfig) { c.reservePause = d }
}

func withOpener(fn func(string, int, os.FileMode) (*os.File, error)) auditOption {
	return func(c *auditConfig) { c.opener = fn }
}

// OpenAudit never fails: an unusable file yields a log in the failed state,
// which refuses every acknowledgement and therefore every admission.
func OpenAudit(path string, s Settings) *AuditLog {
	return openAuditWith(path, s)
}

func openAuditWith(path string, s Settings, opts ...auditOption) *AuditLog {
	cfg := auditConfig{reservePause: defaultReservePause, opener: os.OpenFile}
	for _, opt := range opts {
		opt(&cfg)
	}
	a := &AuditLog{
		boot:          NewRequestID()[:16],
		path:          path,
		maxBytes:      s.MaxBytes,
		maxFiles:      s.MaxFiles,
		opener:        cfg.opener,
		evict:         s.WhenFull == FullEvict && s.Archive != "",
		window:        s.Window,
		prefill:       prefillSupported && !s.Append,
		privacy:       s.Privacy,
		outcomeWindow: s.OutcomeWindow,
		signer:        s.Signer,
		queue:         make(chan *auditEntry, max(s.Queue, AuditQueueSize)),
		evictCh:       make(chan *auditEntry, 1),
		done:          make(chan struct{}),
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
	if s.OutcomeWindow > 0 {
		if err := a.reconcile(a.size); err != nil {
			a.openErr = err
			a.Fail(fmt.Errorf("reconciling the audit log: %w", err))
		}
	}
	if s.Reserve > 0 {
		a.reservePath = reserveName(path)
		a.evictReservePath = evictReserveName(path)
	}
	if s.Archive != "" {
		a.archive = newArchiver(a, s)
		a.archive.pause = cfg.reservePause
		go a.archive.run()
	}
	go a.run()
	return a
}

func (a *AuditLog) openFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	if a.opener != nil {
		return a.opener(name, flag, perm)
	}
	return os.OpenFile(name, flag, perm)
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

	set, err := rotatedFiles(a.path, a.maxBytes)
	if err != nil {
		return -1, err
	}
	a.rotated, a.rotatedBytes = set.count, set.bytes
	// 0600 keeps the audit file readable and writable only by the gateway's
	// user: set on creation, and again on a file an earlier version or an
	// operator left with a wider mode.
	file, err := a.openFile(a.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return -1, err
	}
	a.file = file
	if err := file.Chmod(0o600); err != nil {
		return -1, err
	}
	if err := filecheck.SyncDir(filepath.Dir(a.path)); err != nil {
		return -1, err
	}
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
func incompleteRecord(file io.ReaderAt, end int64) (int64, error) {
	if end == 0 {
		return -1, nil
	}
	start := max(end-MaxRecordBytes, 0)
	tail := make([]byte, end-start)
	if err := readAt(file, tail, start); err != nil {
		return -1, err
	}
	if tail[len(tail)-1] == '\n' {
		return -1, nil
	}
	return start + int64(bytes.LastIndexByte(tail, '\n')+1), nil
}

// rotate trims the active file to its logical end, closes it, renames it to
// the next rotated name, opens a new active file and wakes the archiver;
// makeRoom has checked there is room for it. Every batch was synced when written, so closing loses nothing,
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
	rotated, err := a.freeName(time.Now())
	if err != nil {
		return "", err
	}
	if err := os.Rename(a.path, rotated); err != nil {
		return "", err
	}
	fault.CrashPoint("audit-after-rename")
	// 0600 keeps a new audit file readable and writable only by the gateway's user.
	file, err := a.openFile(a.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	a.file, a.size, a.filled = file, 0, 0
	// The rename and the new file are durable before any record goes in it.
	if err := filecheck.SyncDir(filepath.Dir(a.path)); err != nil {
		return "", err
	}
	a.rotated++
	a.rotatedBytes += closed
	a.publishUsage()
	a.archive.signal()
	return filepath.Base(rotated), nil
}

// Usage reports the active file's size and the number of files, each with
// its limit, as last stored by the writer.
func (a *AuditLog) Usage() (activeBytes, activeLimit, files, filesLimit int64) {
	return a.activeBytes.Load(), a.maxBytes, a.files.Load(), int64(a.maxFiles)
}

// Failed reports whether the log refuses new records: it has failed, its
// folder is full under FullRefuse, the file system has no space, or the
// active file is being replaced.
func (a *AuditLog) Failed() bool {
	return a.currentHealth() != healthWriting
}

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
