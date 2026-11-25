// The archiver: one goroutine beside the writer. After each rotation, and
// every archiveCheck, it compresses each rotated file in the active folder
// into the archive folder (or, while that folder fails, into the active
// folder), records audit.archived through the writer and only then deletes
// the original; it moves files compressed in the active folder once the
// archive works again. Under FullEvict it then keeps both folders within
// their bounds and the disks above their free-space threshold by evicting
// the oldest files, each recorded first (evict.go), and it keeps the reserve
// file. It never runs on the request path and never holds the writer: its
// records queue like any other caller's.

package audit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/fault"
	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
)

// archiveCheck is how often the archiver looks without a rotation: the
// folders' state, the disks' free space and the archive's health (the
// kubelet's housekeeping interval).
const archiveCheck = 10 * time.Second

// reservePause is how long the reserve is not made again after a release,
// so a disk near full does not release and rewrite it over and over (the
// kubelet waits its eviction-pressure transition period the same way).
var reservePause = time.Minute

// recordWait bounds one wait for an archiver record; past it the file is
// left for the next pass.
const recordWait = 30 * time.Second

type archiver struct {
	log            *AuditLog
	live           string // the active file's folder
	dir            string // the archive folder
	budget         int64  // the archive folder's bound; 0 for none
	plain          bool   // move rotated files uncompressed
	minFree        float64
	reserve        int64
	generalReserve int64
	evictReserve   int64
	wake           chan struct{}
	stop           chan struct{}
	done           chan struct{}
	halted         sync.Once
	ctx            context.Context
	cancel         context.CancelFunc
	// Published for the metrics and alerts: whether the archive folder
	// took the last probe, its bytes, the rotated files not yet archived,
	// the disks' free bytes (-1 unknown), pressure evictions and the
	// reserve bytes in place.
	usable                 atomic.Bool
	stored, waiting        atomic.Int64
	freeLog, freeArchive   atomic.Int64
	totalLog, totalArchive atomic.Int64
	pressure               atomic.Int64
	held                   atomic.Int64
	failing                bool // the archive failed at the last pass; archiver only
	// spaceSeen is the spaceFails count last answered by an eviction; archiver only.
	spaceSeen uint64
	// released and evictReleased record when each reserve was last released (Unix ns).
	released      atomic.Int64
	evictReleased atomic.Int64
	pause         time.Duration
}

func newArchiver(log *AuditLog, s Settings) *archiver {
	ctx, cancel := context.WithCancel(context.Background())
	general, evict := reserveSplit(s.Reserve)
	r := &archiver{log: log, live: filepath.Dir(log.path), dir: s.Archive, budget: s.ArchiveBytes, plain: s.Plain,
		minFree: float64(s.MinFree) / 100, reserve: s.Reserve, generalReserve: general, evictReserve: evict, pause: reservePause, wake: make(chan struct{}, 1), stop: make(chan struct{}),
		done: make(chan struct{}), ctx: ctx, cancel: cancel}
	r.usable.Store(true)
	r.freeLog.Store(-1)
	r.freeArchive.Store(-1)
	return r
}

// signal wakes the archiver without waiting; nil (no archiver) ignores it.
func (r *archiver) signal() {
	if r == nil {
		return
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *archiver) run() {
	defer close(r.done)
	tick := time.NewTicker(archiveCheck)
	defer tick.Stop()
	for {
		r.pass()
		select {
		case <-r.stop:
			return
		case <-r.wake:
		case <-tick.C:
		}
	}
}

// halt stops the archiver and waits, until ctx ends, for its pass to end.
// A file half done stays as it was and is done at the next start.
func (r *archiver) halt(ctx context.Context) {
	if r == nil {
		return
	}
	r.halted.Do(func() {
		r.cancel()
		close(r.stop)
	})
	select {
	case <-r.done:
	case <-ctx.Done():
	}
}

// pass archives what is waiting, then evicts and keeps the reserve.
func (r *archiver) pass() {
	r.note(r.probe())
	files, err := RotatedFiles(r.log.path, r.dir)
	if err != nil {
		slog.Error("listing security log files", "error", err)
		return
	}
	for _, f := range files {
		if r.ctx.Err() != nil {
			return
		}
		if f.Dir != r.live {
			continue
		}
		if err := r.archive(f); err != nil {
			slog.Error("archiving a security log file; retried at the next pass", "file", f.Name, "error", err)
			break
		}
	}
	if r.log.evict {
		r.trim()
	}
	r.keepReserve()
	r.measure()
}

// archive compresses or moves one rotated file of the active folder,
// records it and deletes the original. A compressed file waits in the
// active folder while the archive cannot take it; uncompressed moves need
// the archive.
func (r *archiver) archive(f RotatedFile) error {
	target, where := r.live, "live"
	if r.usable.Load() && !r.over() {
		target, where = r.dir, "archive"
	}
	var e Event
	var err error
	switch {
	case target == r.live && (f.Packed || r.plain):
		return nil
	case f.Packed || r.plain:
		e, err = place(f, target)
	default:
		e, err = pack(f.Path(), target)
	}
	if err != nil {
		if target == r.dir {
			r.usable.Store(false)
		}
		return err
	}
	e.Kind, e.File, e.Target = "audit.archived", f.Plain(), where
	if err := r.record(e); err != nil {
		return err
	}
	fault.CrashPoint("audit-archive-before-delete")
	return errors.Join(os.Remove(f.Path()), filecheck.SyncDir(r.live))
}

// over reports whether the archive is at its bound under FullRefuse, which
// never deletes: archiving then stops and the active folder fills.
func (r *archiver) over() bool {
	return !r.log.evict && r.budget > 0 && r.stored.Load() >= r.budget
}

// record writes e through the writer and waits until it is synced. The
// wait is not cancelled by halt: a record the writer already took is
// written, so the deletion it announces must follow.
func (r *archiver) record(e Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), recordWait)
	defer cancel()
	return r.log.Commit(ctx, e)
}

// place copies f into dir under the same name (temporary name, sync,
// rename, folder sync) and returns its description.
func place(f RotatedFile, dir string) (Event, error) {
	e, err := describeStored(f)
	if err != nil {
		return Event{}, err
	}
	target := filepath.Join(dir, f.Name)
	temporary := target + ".tmp"
	if err := copyFile(f.Path(), temporary); err != nil {
		return Event{}, errors.Join(err, os.Remove(temporary))
	}
	if err := os.Rename(temporary, target); err != nil {
		return Event{}, errors.Join(err, os.Remove(temporary))
	}
	e.Archived = f.Bytes
	return e, filecheck.SyncDir(dir)
}

// copyFile copies src to a new file dst and syncs it.
func copyFile(src, dst string) error {
	in, err := OpenShared(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// 0600 keeps an archived file readable only by the gateway's user.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	return errors.Join(err, out.Close())
}

// probe checks the archive folder takes a synced write, creating it first.
func (r *archiver) probe() bool {
	// 0700 keeps the archive folder the gateway's own.
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return false
	}
	path := filepath.Join(r.dir, ".probe")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_, err = file.Write([]byte{'\n'})
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close(), os.Remove(path))
	return err == nil
}

// note publishes the archive's health and logs each change once.
func (r *archiver) note(usable bool) {
	r.usable.Store(usable)
	switch {
	case !usable && !r.failing:
		slog.Error("security log archive folder unavailable; rotated files are compressed in the log folder until it works", "archive", r.dir)
	case usable && r.failing:
		slog.Info("security log archive folder available again", "archive", r.dir)
	}
	r.failing = !usable
}
