// Rotated audit file names: <name>-<UTC time>.<ext>, the time to the
// millisecond (the scheme of Go's lumberjack writer), so a name never
// repeats after files are moved away and names sort by age. A compressed
// file adds ".gz"; files named <name>.<n> by earlier versions are still
// listed, older than any other. A rotated file lives in the active file's
// folder until the archiver moves it to the archive folder.

package audit

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// rotatedLayout is the time in a rotated file's name; it holds no colon,
// which Windows refuses in file names.
const rotatedLayout = "2006-01-02T15-04-05.000"

// packedSuffix marks a gzip-compressed file; evictedSuffix an empty
// tombstone naming a file evicted while older files remained.
const (
	packedSuffix  = ".gz"
	evictedSuffix = ".evicted"
)

// RotatedFile is one rotated file of the log. Name is its stored base name;
// Plain is the name audit.rotated records, without ".gz". Number is set for
// a file an earlier version named <name>.<n>; Rotated for the others.
type RotatedFile struct {
	Name    string
	Dir     string
	Rotated time.Time
	Number  int
	Bytes   int64
	Packed  bool
}

// Path is the file's full path.
func (f RotatedFile) Path() string { return filepath.Join(f.Dir, f.Name) }

// Plain is the file's name before compression.
func (f RotatedFile) Plain() string { return strings.TrimSuffix(f.Name, packedSuffix) }

// rotatedName is the path a file rotated at at gets.
func rotatedName(active string, at time.Time) string {
	dir, base := filepath.Split(active)
	ext := filepath.Ext(base)
	return filepath.Join(dir, strings.TrimSuffix(base, ext)+"-"+at.UTC().Format(rotatedLayout)+ext)
}

// RotatedFiles lists the rotated files of the active file in its folder and
// in archive ("" for none), oldest first, one entry per plain name: while a
// file is being compressed both copies exist, and the original is listed.
// An archive folder that cannot be read (unmounted, removed) adds nothing.
func RotatedFiles(active, archive string) ([]RotatedFile, error) {
	files, err := listRotated(filepath.Dir(active), filepath.Base(active))
	if err != nil {
		return nil, err
	}
	if archive != "" {
		archived, err := listRotated(archive, filepath.Base(active))
		if err == nil {
			files = append(files, archived...)
		}
	}
	slices.SortFunc(files, func(a, b RotatedFile) int {
		return cmp.Or(compareAge(a, b), cmp.Compare(boolRank(a.Packed), boolRank(b.Packed)))
	})
	return slices.CompactFunc(files, func(a, b RotatedFile) bool { return a.Plain() == b.Plain() }), nil
}

// listRotated lists the rotated files of base found in dir.
func listRotated(dir, base string) ([]RotatedFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext) + "-"
	var files []RotatedFile
	for _, entry := range entries {
		file, ok := parseRotated(entry.Name(), base, stem, ext)
		if !ok {
			continue
		}
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue // moved away while listed
		}
		if err != nil {
			return nil, err
		}
		file.Dir, file.Bytes = dir, info.Size()
		files = append(files, file)
	}
	return files, nil
}

// compareAge orders earlier-version files first, by number, then by time.
func compareAge(a, b RotatedFile) int {
	switch earlierA, earlierB := a.Number > 0, b.Number > 0; {
	case earlierA && earlierB:
		return cmp.Compare(a.Number, b.Number)
	case earlierA:
		return -1
	case earlierB:
		return 1
	}
	return a.Rotated.Compare(b.Rotated)
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// parseRotated reads name as a rotated file of base: <stem><time><ext> or
// the earlier <base>.<n>, either with ".gz".
func parseRotated(name, base, stem, ext string) (RotatedFile, bool) {
	plain, packed := strings.CutSuffix(name, packedSuffix)
	file := RotatedFile{Name: name, Packed: packed}
	if suffix, found := strings.CutPrefix(plain, base+"."); found {
		if n, err := strconv.Atoi(suffix); err == nil && n >= 1 && strconv.Itoa(n) == suffix {
			file.Number = n
			return file, true
		}
	}
	middle, found := strings.CutPrefix(plain, stem)
	if !found || !strings.HasSuffix(middle, ext) {
		return RotatedFile{}, false
	}
	at, err := time.Parse(rotatedLayout, strings.TrimSuffix(middle, ext))
	if err != nil {
		return RotatedFile{}, false
	}
	file.Rotated = at
	return file, true
}

// Tombstones lists the plain names of files evicted while an older file
// remained; readers report them as evicted rather than missing.
func Tombstones(active string) (map[string]bool, error) {
	entries, err := os.ReadDir(filepath.Dir(active))
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, entry := range entries {
		if plain, found := strings.CutSuffix(entry.Name(), evictedSuffix); found {
			names[plain] = true
		}
	}
	return names, nil
}

// freeName is the name a file rotated at at gets: later than the last name
// used, and a millisecond later for each name taken in the log or archive
// folder, plain or compressed, so a name never repeats and an eviction
// record never names two files.
func (a *AuditLog) freeName(at time.Time) (string, error) {
	if !at.After(a.lastName) {
		at = a.lastName.Add(time.Millisecond)
	}
	dirs := []string{filepath.Dir(a.path)}
	if a.archive != nil {
		dirs = append(dirs, a.archive.dir)
	}
	for {
		name := rotatedName(a.path, at)
		taken, err := anyExists(dirs, filepath.Base(name), filepath.Base(name)+packedSuffix)
		if err != nil {
			return "", err
		}
		if !taken {
			a.lastName = at
			return name, nil
		}
		at = at.Add(time.Millisecond)
	}
}

// anyExists reports whether any of names exists in any of dirs.
func anyExists(dirs []string, names ...string) (bool, error) {
	for _, dir := range dirs {
		for _, name := range names {
			_, err := os.Lstat(filepath.Join(dir, name))
			if err == nil {
				return true, nil
			}
			// A folder that is missing, or is a file, holds no such name.
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
				return false, err
			}
		}
	}
	return false, nil
}
