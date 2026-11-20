// The audit log's state: what the writer owns, what readers outside it may
// load, and how a failure that no recovery covers stops admission.

package audit

import (
	"crypto/sha256"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// AuditLog writes events to a local file. Events that gate a decision wait
// until the batch containing them has been synced to disk; other events are
// queued without blocking and counted when they cannot be queued.
//
// An event is accepted when enqueue puts it in the queue. Every accepted event
// is written in order by the one writer, which ends only once close has
// closed the queue and every event in it has been written; so a close that
// returns nil means every accepted event, and the count of every refused one,
// is in the file and synced.
//
// On Linux, unless the settings ask to append, the active file is filled with
// zero bytes ahead of the writer and written in place; its content ends at
// End. The active file is rotated to a time-named file before it would
// exceed maxBytes; the archiver (archive.go) compresses rotated files, moves
// them to the archive folder and evicts the oldest, each recorded first.
// Under FullRefuse the log refuses records, and so protected admission, once
// the active folder holds maxFiles × maxBytes, until files are moved away.
type AuditLog struct {
	boot     string // distinguishes event identities across runs; writer only
	path     string
	maxBytes int64
	maxFiles int
	file     *os.File // used only by the writer, which closes it as it ends
	size     int64    // logical size of the active file; used only by the writer
	// prefill zero-fills the active file ahead of the writer up to filled,
	// its physical size (see fill.go); used only by the writer.
	prefill bool
	filled  int64
	rotated int // rotated files in the active folder; used only by the writer
	// rotatedBytes is their total size; used only by the writer.
	rotatedBytes int64
	// encoded is the last batch's memory, reused by the next batch; used
	// only by the writer.
	encoded []byte
	// seq numbers records in file order; used only by the writer.
	seq uint64
	// marker names the rotated file the next write must record first, set
	// when a rotation's marker is not yet written; used only by the writer.
	marker string
	evict  bool // the archiver deletes the oldest files, recorded first
	// privacy is how client addresses are recorded; never changes.
	privacy Privacy
	// outcomeWindow bounds reconciliation after an unclean stop.
	outcomeWindow time.Duration
	// head is the chain head of the batches written in this run, and
	// signer signs its checkpoints (chain.go); used only by the writer.
	head   [sha256.Size]byte
	signer Signer
	// published copies head for readers outside the writer (ChainHead).
	published atomic.Pointer[[sha256.Size]byte]
	// window is how long a batch with siblings waits for more events
	// before its sync; 0 syncs each batch as soon as it is drained.
	window  time.Duration
	openErr error // why openAudit could not open the file; never changes
	queue   chan *auditEntry
	failed  atomic.Bool
	full    atomic.Bool // the active folder is at its bound under FullRefuse
	// noSpace is set while the file system has no space for a write; the
	// writer clears it once a retried write and its sync succeed.
	noSpace atomic.Bool
	// down is set while the active file is being replaced after a failed
	// sync or write (recover.go); the writer clears it.
	down atomic.Bool
	// spaceSince is when the log ran out of space; downSince when it went
	// down, suspect the file it left and suspectEnd the end of its last
	// synced batch; used only by the writer.
	spaceSince, downSince time.Time
	downReason, suspect   string
	suspectEnd            int64
	// fresh marks an active file opened by a recovery that holds no synced
	// record yet, and replaced is when the last replacement began; used
	// only by the writer.
	fresh    bool
	replaced time.Time
	// lastName is the time in the last rotated name, which only rises;
	// used only by the writer.
	lastName time.Time
	// reservePath is the reserve file ("" for none), released by the
	// writer when the file system has no space (reserve.go).
	reservePath string
	// archive moves, compresses and evicts rotated files; nil without an
	// archive folder.
	archive *archiver
	lost    atomic.Uint64 // events refused and not yet counted in the file
	// lossTotal, evictions and recoveries count, since the start, the
	// refused events written in loss records, the files evicted and the
	// files replaced after a failed sync, for the metrics.
	lossTotal  atomic.Uint64
	evictions  atomic.Uint64
	recoveries atomic.Int64
	accepted   atomic.Uint64 // events queued
	// activeBytes and files copy size and rotated+1 for readers outside the
	// writer (the limits read); only the writer stores them.
	activeBytes atomic.Int64
	files       atomic.Int64
	usedBytes   atomic.Int64 // the active folder's bytes
	summary     ingressSummary
	saves       saves
	written     atomic.Uint64 // queued events written and synced
	// mu orders queueing against closing: enqueue holds it shared while it
	// checks closing and queues, and close holds it exclusively while it sets
	// closing and closes the queue. Neither blocks while holding it.
	mu      sync.RWMutex
	closing bool
	done    chan struct{} // closed when the writer has ended
	fileErr error         // the result of closing the file; set by the writer before done
}

// Fail stops admission until a restart: for a log that never opened, or an
// administrator outcome that could not be recorded (its reconciliation runs
// at the next start).
func (a *AuditLog) Fail(err error) {
	if a.failed.CompareAndSwap(false, true) {
		slog.Error("audit log failed; protected admission disabled", "error", err)
	}
}
