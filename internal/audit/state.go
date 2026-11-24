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

	"github.com/Alex-Zechariah-02/apiward/internal/disk"
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
		d, err := disk.Of(side.dir)
		if err != nil {
			d.Free, d.Total = -1, -1
		}
		side.free.Store(d.Free)
		side.total.Store(d.Total)
	}
}

// keepReserve makes each reserve file when it is missing and the disk has
// room for it above the free-space threshold, reporting the sum of both in
// r.held.
func (r *archiver) keepReserve() {
	var held int64
	for _, item := range []struct {
		path     string
		size     int64
		released *atomic.Int64
	}{
		{r.log.reservePath, r.generalReserve, &r.released},
		{r.log.evictReservePath, r.evictReserve, &r.evictReleased},
	} {
		if item.path == "" || item.size <= 0 {
			continue
		}
		if _, err := os.Stat(item.path); err == nil {
			held += item.size
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			slog.Error("checking the audit reserve", "path", item.path, "error", err)
			continue
		}
		if time.Since(time.Unix(0, item.released.Load())) < r.pause {
			continue
		}
		d, err := disk.Of(r.live)
		if err != nil || (d.Total > 0 && (d.Below(r.minFree, 2*r.reserve) || d.Free-item.size < int64(r.minFree*float64(d.Total)))) {
			continue
		}
		if err := makeReserve(item.path, item.size); err != nil {
			slog.Error("making the audit reserve; retried at the next pass", "path", item.path, "error", err)
			continue
		}
		held += item.size
	}
	r.held.Store(held)
}
