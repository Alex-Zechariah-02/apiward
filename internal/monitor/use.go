// Permission use read from the security log for the advice checks: each
// file is scanned newest first within a byte budget, and a rotated file's
// summary is kept so an unchanged file is not read again.

package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
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
	mu    sync.Mutex
	files map[string]summary
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
// full read took, so the answer is the same as a full read's.
func (c *Summaries) PermitUse(dir string, files []string, scan int64) (LogUse, error) {
	use := LogUse{used: map[[2]string]bool{}, Searched: []string{}, complete: true}
	budget := scan
	defer c.prune(files)
	for i, name := range files {
		if budget <= 0 {
			use.complete = false
			break
		}
		part, stopped, err := c.read(filepath.Join(dir, name), i > 0, &budget)
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
func (c *Summaries) read(path string, rotated bool, budget *int64) (fileUse, bool, error) {
	var info os.FileInfo
	if rotated {
		var err error
		if info, err = os.Stat(path); err != nil {
			return fileUse{}, false, err
		}
		if entry, ok := c.lookup(info); ok && *budget >= entry.cost {
			*budget -= entry.cost
			return entry.use, false, nil
		}
	}
	part := fileUse{used: map[[2]string]bool{}}
	before := *budget
	_, stopped, err := scanLinesBackward(path, -1, budget, part.visit)
	if err == nil && rotated && !stopped {
		c.store(summary{size: info.Size(), mod: info.ModTime(), cost: before - *budget, use: part}, info.Name())
	}
	return part, stopped, err
}

// visit counts one line if it is a request's final record.
func (u *fileUse) visit(line []byte, _ int64) bool {
	if !bytes.Contains(line, rejectedKind) && !bytes.Contains(line, forwardedKind) {
		return false
	}
	var record auditRequestRecord
	if json.Unmarshal(line, &record) != nil || record.RequestID == "" {
		return false
	}
	u.requests++
	if u.oldest.IsZero() || record.Time.Before(u.oldest) {
		u.oldest = record.Time
	}
	if record.Decision == "forwarded" {
		for _, role := range record.Roles {
			u.used[[2]string{role, record.Operation}] = true
		}
	}
	return false
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
