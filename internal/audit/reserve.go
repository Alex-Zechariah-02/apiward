// The reserve file: space set aside on the active file's disk, zero-filled
// and synced so it is really allocated (a ballast file). When a write finds
// no space, the writer deletes it and writes again, so records are still
// saved while the archiver evicts the oldest files; the archiver makes it
// again once the disk has room.

package audit

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
)

// reserveName is the reserve file of the active file: <name>.reserve.
func reserveName(active string) string {
	dir, base := filepath.Split(active)
	return filepath.Join(dir, strings.TrimSuffix(base, filepath.Ext(base))+".reserve")
}

// evictReserveName is the dedicated eviction reserve beside the active file.
func evictReserveName(active string) string {
	return filepath.Join(filepath.Dir(active), "audit.evict.reserve")
}

// evictReserveCap is the dedicated eviction headroom taken out of the reserve
// budget; at or below 1 MiB the budget is split evenly between both files.
const evictReserveCap = 1 << 20

func reserveSplit(budget int64) (general, evict int64) {
	if budget <= 0 {
		return 0, 0
	}
	if budget <= evictReserveCap {
		evict = budget / 2
		return budget - evict, evict
	}
	return budget - evictReserveCap, evictReserveCap
}

// releaseEvictReserve deletes the eviction reserve file and syncs its folder
// so commitEviction can write an audit.evicted record while in noSpace.
func (a *AuditLog) releaseEvictReserve() bool {
	if a.evictReservePath == "" {
		return false
	}
	if err := os.Remove(a.evictReservePath); err != nil {
		return false
	}
	if err := filecheck.SyncDir(filepath.Dir(a.evictReservePath)); err != nil {
		slog.Error("syncing the folder after releasing the eviction reserve", "error", err)
	}
	slog.Warn("audit eviction reserve released to record an eviction while the disk is full", "reserve", a.evictReservePath)
	if a.archive != nil {
		a.archive.evictReleased.Store(time.Now().UnixNano())
	}
	return true
}

// releaseReserve deletes the reserve file so a write that met no space can
// be tried again, and reports whether one was deleted. Only the writer
// calls it.
func (a *AuditLog) releaseReserve() bool {
	if a.reservePath == "" {
		return false
	}
	if err := os.Remove(a.reservePath); err != nil {
		return false
	}
	if err := filecheck.SyncDir(filepath.Dir(a.reservePath)); err != nil {
		slog.Error("syncing the folder after releasing the audit reserve", "error", err)
	}
	slog.Warn("audit reserve released: the disk is full; the oldest security log files are evicted to make room", "reserve", a.reservePath)
	if a.archive != nil {
		a.archive.released.Store(time.Now().UnixNano())
	}
	a.archive.signal()
	return true
}

// makeReserve writes the reserve file at path: size zero bytes, synced,
// then renamed into place, so a partial reserve never counts as one.
func makeReserve(path string, size int64) error {
	temporary := path + ".tmp"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// 0600: the reserve is the gateway's own file.
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = fillZeros(file, size)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporary, path)
	}
	if err != nil {
		return errors.Join(err, os.Remove(temporary))
	}
	return filecheck.SyncDir(filepath.Dir(path))
}

// fillZeros writes size zero bytes to file and syncs them.
func fillZeros(file *os.File, size int64) error {
	for at := int64(0); at < size; {
		n, err := file.WriteAt(zeros[:min(int64(len(zeros)), size-at)], at)
		if err != nil {
			return err
		}
		at += int64(n)
	}
	return file.Sync()
}
