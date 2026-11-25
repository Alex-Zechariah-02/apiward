// Eviction under FullEvict: the oldest files are deleted, each only after a
// synced audit.evicted record naming it, its size, SHA-256 and the times of
// its first and last records, so no deletion is ever without its record.
// The archive is kept within its bound, the active folder within
// maxFiles × maxBytes, and each disk above its free-space threshold (the
// kubelet's disk-pressure eviction, Elasticsearch's watermarks). A file
// evicted while an older one remains leaves a tombstone, so readers report
// it as evicted rather than missing.

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/Alex-Zechariah-02/apiward/internal/disk"
	"github.com/Alex-Zechariah-02/apiward/internal/filecheck"
)

// Reasons an audit.evicted record gives.
const (
	evictArchive  = "archive_budget"
	evictLog      = "log_budget"
	evictPressure = "disk_pressure"
)

// trim evicts until every bound holds or nothing is left to evict.
func (r *archiver) trim() {
	files, err := RotatedFiles(r.log.path, r.dir)
	if err != nil {
		slog.Error("listing security log files for eviction", "error", err)
		return
	}
	for _, rule := range []struct {
		reason string
		pick   func([]RotatedFile) int
	}{
		{evictArchive, r.overArchive},
		{evictLog, r.overLive},
		{evictPressure, r.underPressure},
	} {
		for len(files) > 0 && r.ctx.Err() == nil {
			at := rule.pick(files)
			if at < 0 {
				break
			}
			if err := r.evict(files, at, rule.reason); err != nil {
				slog.Error("evicting a security log file; retried at the next pass", "file", files[at].Name, "error", err)
				return
			}
			files = slices.Delete(files, at, at+1)
		}
	}
	r.sweep(files)
}

// overArchive picks the oldest archived file while the archive exceeds its
// bound, or -1.
func (r *archiver) overArchive(files []RotatedFile) int {
	return oldestOver(files, r.dir, r.budget)
}

// overLive picks the oldest rotated file in the active folder while the
// folder, the active file included, exceeds its bound, or -1.
func (r *archiver) overLive(files []RotatedFile) int {
	return oldestOver(files, r.live, r.log.budget()-r.log.activeBytes.Load())
}

// oldestOver picks the oldest file in dir while the files there hold more
// than bound bytes (bound <= 0 with dir the archive: no bound), or -1.
func oldestOver(files []RotatedFile, dir string, bound int64) int {
	var held int64
	first := -1
	for i, f := range files {
		if f.Dir != dir {
			continue
		}
		held += f.Bytes
		if first < 0 {
			first = i
		}
	}
	if first < 0 || bound <= 0 || held <= bound {
		return -1
	}
	return first
}

// underPressure picks the oldest file on a disk below its free-space
// threshold, or -1. While a reserve is released a disk must also have twice
// the reserve free. Each write refused for want of space also picks one file
// on the log disk, whatever its free space reads (a quota or inode limit).
func (r *archiver) underPressure(files []RotatedFile) int {
	fails := r.log.spaceFails.Load()
	floor := int64(0)
	if r.reserve > 0 && r.held.Load() < r.reserve {
		floor = 2 * r.reserve
	}
	for _, dir := range []string{r.live, r.dir} {
		d, err := disk.Of(dir)
		full := dir == r.live && r.log.noSpace.Load() && fails != r.spaceSeen
		if err != nil || !full && !d.Below(r.minFree, floor) {
			continue
		}
		for i, f := range files {
			if same, err := disk.Of(f.Dir); err == nil && same.ID == d.ID {
				if full {
					r.spaceSeen = fails
				}
				return i
			}
		}
	}
	return -1
}

// evict records files[at] and deletes it; a file newer than another still
// present leaves a tombstone first.
func (r *archiver) evict(files []RotatedFile, at int, reason string) error {
	f := files[at]
	e, err := describeStored(f)
	if err != nil {
		return err
	}
	digest, err := fileDigest(f.Path())
	if err != nil {
		return err
	}
	where := "live"
	if f.Dir == r.dir {
		where = "archive"
	}
	e.Kind, e.File, e.Bytes, e.Digest, e.Reason, e.Target, e.Archived = "audit.evicted", f.Plain(), f.Bytes, digest, reason, where, 0
	if err := r.recordEviction(e); err != nil {
		return err
	}
	if at > 0 {
		if err := tombstone(r.live, f.Plain()); err != nil {
			return err
		}
	}
	if err := errors.Join(os.Remove(f.Path()), filecheck.SyncDir(f.Dir)); err != nil {
		return err
	}
	r.log.evictions.Add(1)
	if reason == evictPressure {
		r.pressure.Add(1)
	}
	return nil
}

// recordEviction writes an audit.evicted record through commitEviction so it
// can use the eviction reserve while the log refuses other writes for noSpace.
func (r *archiver) recordEviction(e Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), recordWait)
	defer cancel()
	return r.log.commitEviction(ctx, e)
}

// describeStored describes a file: from its gzip header when compressed,
// else by reading it.
func describeStored(f RotatedFile) (Event, error) {
	if !f.Packed {
		return describe(f.Path(), "")
	}
	p, err := ReadPacked(f.Path())
	if err != nil {
		return Event{}, err
	}
	return Event{File: f.Plain(), Bytes: p.Bytes, Digest: p.Digest, First: p.First, Last: p.Last}, nil
}

// fileDigest is the SHA-256 of the file as stored.
func fileDigest(path string) (string, error) {
	file, err := OpenShared(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// tombstone writes the empty, synced file <name>.evicted in dir.
func tombstone(dir, name string) error {
	// 0600: the tombstone is the gateway's own file.
	file, err := os.OpenFile(filepath.Join(dir, name+evictedSuffix), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return errors.Join(file.Close(), filecheck.SyncDir(dir))
}

// sweep removes tombstones no reader needs: those of files present again and
// those older than the oldest file present, whose gap is never checked.
func (r *archiver) sweep(files []RotatedFile) {
	names, err := Tombstones(r.log.path)
	if err != nil || len(names) == 0 {
		return
	}
	base := filepath.Base(r.log.path)
	ext := filepath.Ext(base)
	stem := base[:len(base)-len(ext)] + "-"
	for name := range names {
		gone, ok := parseRotated(name, base, stem, ext)
		present := slices.ContainsFunc(files, func(f RotatedFile) bool { return f.Plain() == name })
		if ok && !present && len(files) > 0 && compareAge(gone, files[0]) > 0 {
			continue
		}
		if err := os.Remove(filepath.Join(r.live, name+evictedSuffix)); err != nil {
			slog.Error("removing a security log tombstone", "name", name, "error", err)
		}
	}
}
