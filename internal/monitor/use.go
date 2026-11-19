// Permission use read from the security log for the advice checks: each
// file is scanned newest first within a byte budget. A rotated file's
// summary is kept so an unchanged file is not read again, and the active
// file's summary covers the part already read, so only what was appended
// since is read.

package monitor

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
)

// LogUse is what the security log shows about permission use: the role and
// endpoint pairs of allowed requests, how many request records were read and
// how far back they reach.
type LogUse struct {
	used     map[[2]string]bool
	requests int
	oldest   time.Time
	complete bool
	Searched []string
}

// fileUse is one file's share of a LogUse.
type fileUse struct {
	used     map[[2]string]bool
	requests int
	oldest   time.Time
}

// Summaries keeps the fileUse of each rotated file read in full, keyed by
// its name and checked against its size and modification time; rotated
// files do not change. An entry goes when its file is no longer listed. The
// zero value is ready to use.
type Summaries struct {
	mu     sync.Mutex
	files  map[string]summary
	active *prefix
}

// prefix is the use read from the active file up to end, a line start. It
// holds while the file keeps its first record (no rotation), is no shorter
// than end, and its newest record was written by the same gateway start (boot
// ID): a start may rewrite an unfinished last record, so a new start reads
// the file again.
type prefix struct {
	name, first, boot string
	end, cost         int64
	use               fileUse
}

// summary is a rotated file's use and cost, the scan budget its full read
// took: more than its size, as the line cut at each window edge is read
// again with the next window.
type summary struct {
	size int64
	mod  time.Time
	cost int64
	use  fileUse
}

// PermitUse reads the request records of the security log files, listed as
// LogFiles lists them (the active file first), newest first, at most scan
// bytes. A rotated file with a summary is not read but takes the budget its
// full read took, so the answer is the same as a full read's. It stops with
// ctx's error once ctx ends.
func (c *Summaries) PermitUse(ctx context.Context, dir string, files []string, scan int64) (LogUse, error) {
	use := LogUse{used: map[[2]string]bool{}, Searched: []string{}, complete: true}
	budget := scan
	defer c.prune(files)
	for i, name := range files {
		if budget <= 0 {
			use.complete = false
			break
		}
		read := c.read
		if i == 0 {
			read = c.readActive
		}
		part, stopped, err := read(ctx, filepath.Join(dir, name), &budget)
		if errors.Is(err, os.ErrNotExist) {
			continue // archived since it was listed
		}
		if err != nil {
			return use, err
		}
		use.add(part)
		use.Searched = append(use.Searched, name)
		if stopped {
			use.complete = false
			break
		}
	}
	return use, nil
}

// read gives one file's use, from its summary when the file is rotated,
// unchanged and within the budget, else by scanning it; a rotated file read
// in full gets a summary.
func (c *Summaries) read(ctx context.Context, path string, budget *int64) (fileUse, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileUse{}, false, err
	}
	if entry, ok := c.lookup(info); ok && *budget >= entry.cost {
		*budget -= entry.cost
		return entry.use, false, nil
	}
	part := fileUse{used: map[[2]string]bool{}}
	before := *budget
	_, stopped, err := scanLinesBackward(ctx, path, -1, 0, budget, part.visit)
	if err == nil && !stopped {
		c.store(summary{size: info.Size(), mod: info.ModTime(), cost: before - *budget, use: part}, info.Name())
	}
	return part, stopped, err
}

// readActive gives the active file's use: the kept prefix's when it still
// holds and fits the budget, plus the records appended since; else a scan of
// the whole file. A prefix is charged the budget its reads took, which may
// differ from one whole read by the lines cut at window edges, so a
// later file can be read a little further than one whole read would reach;
// what is read is still exact.
func (c *Summaries) readActive(ctx context.Context, path string, budget *int64) (fileUse, bool, error) {
	first, err := firstRecordID(path)
	if err != nil {
		return fileUse{}, false, err
	}
	name := filepath.Base(path)
	c.mu.Lock()
	kept := c.active
	c.mu.Unlock()
	if kept == nil || kept.name != name || kept.first != first || *budget < kept.cost {
		kept = &prefix{name: name, first: first, use: fileUse{used: map[[2]string]bool{}}}
	}
	return c.extend(ctx, path, kept, budget)
}

// extend reads the records appended after kept and keeps the longer prefix.
func (c *Summaries) extend(ctx context.Context, path string, kept *prefix, budget *int64) (fileUse, bool, error) {
	remaining := *budget - kept.cost
	part := fileUse{used: map[[2]string]bool{}}
	boot := ""
	end, stopped, err := scanLinesBackward(ctx, path, -1, kept.end, &remaining, func(line []byte, at int64) bool {
		if boot == "" {
			boot = bootOf(line)
		}
		return part.visit(line, at)
	})
	if err != nil {
		return fileUse{}, false, err
	}
	// A shorter file or a new start's records: read the whole file again.
	if kept.end > 0 && (end < kept.end || (boot != "" && boot != kept.boot)) {
		return c.extend(ctx, path, &prefix{name: kept.name, first: kept.first, use: fileUse{used: map[[2]string]bool{}}}, budget)
	}
	use := part
	use.add(kept.use)
	cost := *budget - remaining
	*budget = remaining
	if !stopped {
		c.mu.Lock()
		c.active = &prefix{name: kept.name, first: kept.first, boot: cmp.Or(boot, kept.boot), end: end, cost: cost, use: use}
		c.mu.Unlock()
	}
	return use, stopped, nil
}

// bootOf is the boot ID of a record: its event ID up to the first hyphen.
func bootOf(line []byte) string {
	_, rest, found := bytes.Cut(line, []byte(`"event_id":"`))
	if !found {
		return ""
	}
	boot, _, found := bytes.Cut(rest, []byte("-"))
	if !found || len(boot) > 64 {
		return ""
	}
	return string(boot)
}

// visit counts one line if it is a request's final record. A permission
// counts as used once its request passed the role check, also when a later
// stage or the service refused it: an outage must not make permits look
// unused.
func (u *fileUse) visit(line []byte, _ int64) bool {
	if !bytes.Contains(line, rejectedKind) && !bytes.Contains(line, forwardedKind) {
		return false
	}
	record, ok := decodeRecord(line)
	if !ok {
		return false
	}
	u.requests++
	if u.oldest.IsZero() || record.Time.Before(u.oldest) {
		u.oldest = record.Time
	}
	if record.Decision == "forwarded" || slices.Index(audit.StageNames[:], record.Stage) > audit.StageRBAC {
		for _, role := range record.Roles {
			u.used[[2]string{role, record.Operation}] = true
		}
	}
	return false
}

// add merges another file's use into this one.
func (u *fileUse) add(other fileUse) {
	u.requests += other.requests
	if !other.oldest.IsZero() && (u.oldest.IsZero() || other.oldest.Before(u.oldest)) {
		u.oldest = other.oldest
	}
	for pair := range other.used {
		u.used[pair] = true
	}
}

func (u *LogUse) add(part fileUse) {
	u.requests += part.requests
	if !part.oldest.IsZero() && (u.oldest.IsZero() || part.oldest.Before(u.oldest)) {
		u.oldest = part.oldest
	}
	for pair := range part.used {
		u.used[pair] = true
	}
}

func (c *Summaries) lookup(info os.FileInfo) (summary, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.files[info.Name()]
	if !ok || entry.size != info.Size() || !entry.mod.Equal(info.ModTime()) {
		return summary{}, false
	}
	return entry, true
}

func (c *Summaries) store(entry summary, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.files == nil {
		c.files = map[string]summary{}
	}
	c.files[name] = entry
}

// prune drops the summaries of files no longer listed.
func (c *Summaries) prune(files []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	listed := make(map[string]bool, len(files))
	for _, name := range files {
		listed[name] = true
	}
	for name := range c.files {
		if !listed[name] {
			delete(c.files, name)
		}
	}
}
