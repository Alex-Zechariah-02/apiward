// What the archiver last measured, for the metrics, the alerts and the
// limits read, and the reserve file it keeps.

package audit

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// ArchiveState is the archiver's last measurement: the archive folder and
// whether it took the last probe, its bytes and bound, the rotated files not
// yet archived, the free bytes of the log's and the archive's disks (-1
// unknown), the free-space threshold, the reserve bytes in place and the
// evictions made for disk pressure.
type ArchiveState struct {
	Folder                 string
	Usable                 bool
	Bytes, Budget          int64
	Waiting                int64
	FreeLog, FreeArchive   int64
	TotalLog, TotalArchive int64
	MinFree                float64
	Reserve, ReserveSize   int64
	Pressure               int64
}

// ArchivePath is the archive folder, "" without an archiver.
func (a *AuditLog) ArchivePath() string {
	if a.archive == nil {
		return ""
	}
	return a.archive.dir
}

// Archive reports the archiver's state; false without an archiver.
func (a *AuditLog) Archive() (ArchiveState, bool) {
	r := a.archive
	if r == nil {
		return ArchiveState{}, false
	}
	return ArchiveState{Folder: r.dir, Usable: r.usable.Load(), Bytes: r.stored.Load(), Budget: r.budget, Waiting: r.waiting.Load(),
		FreeLog: r.freeLog.Load(), FreeArchive: r.freeArchive.Load(), TotalLog: r.totalLog.Load(), TotalArchive: r.totalArchive.Load(), MinFree: r.minFree, Reserve: r.held.Load(),
		ReserveSize: r.reserve, Pressure: r.pressure.Load()}, true
}

// measure publishes the folders' and disks' state.
func (r *archiver) measure() {
	files, err := RotatedFiles(r.log.path, r.dir)
	if err != nil {
		return
	}
	var stored, waiting int64
	for _, f := range files {
		switch {
		case f.Dir == r.dir:
			stored += f.Bytes
		case !f.Packed:
			waiting++
		}
	}
	r.stored.Store(stored)
	r.waiting.Store(waiting)
	for _, side := range []struct {
		dir         string
		free, total *atomic.Int64
	}{{r.live, &r.freeLog, &r.totalLog}, {r.dir, &r.freeArchive, &r.totalArchive}} {
		d, err := diskOf(side.dir)
		if err != nil {
			d.free, d.total = -1, -1
		}
		side.free.Store(d.free)
		side.total.Store(d.total)
	}
}

// keepReserve makes the reserve file when it is missing and the disk has
// room for it above the free-space threshold.
func (r *archiver) keepReserve() {
	path := r.log.reservePath
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err == nil {
		r.held.Store(r.reserve)
		return
	} else if !errors.Is(err, fs.ErrNotExist) {
		slog.Error("checking the audit reserve", "error", err)
		return
	}
	r.held.Store(0)
	if time.Since(time.Unix(0, r.released.Load())) < r.pause {
		return
	}
	d, err := diskOf(r.live)
	if err != nil || (d.total > 0 && (d.below(r.minFree, 2*r.reserve) || d.free-r.reserve < int64(r.minFree*float64(d.total)))) {
		return
	}
	if err := makeReserve(path, r.reserve); err != nil {
		slog.Error("making the audit reserve; retried at the next pass", "error", err)
		return
	}
	r.held.Store(r.reserve)
}
