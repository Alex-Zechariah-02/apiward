// Rotated audit file names: <name>-<UTC time>.<ext>, the time to the
// millisecond (the scheme of Go's lumberjack writer), so a name never
// repeats after files are moved away and names sort by age. Files named
// <name>.<n> by earlier versions are still listed, older than any other.

package audit

import (
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// rotatedLayout is the time in a rotated file's name; it holds no colon,
// which Windows refuses in file names.
const rotatedLayout = "2006-01-02T15-04-05.000"

// RotatedFile is one rotated file of the log, by base name. Number is set
// for a file an earlier version named <name>.<n>; Rotated for the others.
type RotatedFile struct {
	Name    string
	Rotated time.Time
	Number  int
	Bytes   int64
}

// rotatedName is the path a file rotated at at gets.
func rotatedName(active string, at time.Time) string {
	dir, base := filepath.Split(active)
	ext := filepath.Ext(base)
	return filepath.Join(dir, strings.TrimSuffix(base, ext)+"-"+at.UTC().Format(rotatedLayout)+ext)
}

// RotatedFiles lists the rotated files of the active file, oldest first.
func RotatedFiles(active string) ([]RotatedFile, error) {
	entries, err := os.ReadDir(filepath.Dir(active))
	if err != nil {
		return nil, err
	}
	base := filepath.Base(active)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext) + "-"
	var files []RotatedFile
	for _, entry := range entries {
		file, ok := parseRotated(entry.Name(), base, stem, ext)
		if !ok {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			if os.IsNotExist(err) {
				continue // moved away while listed
			}
			return nil, err
		}
		file.Bytes = info.Size()
		files = append(files, file)
	}
	slices.SortFunc(files, func(a, b RotatedFile) int {
		switch earlierA, earlierB := a.Number > 0, b.Number > 0; {
		case earlierA && earlierB:
			return cmp.Compare(a.Number, b.Number)
		case earlierA:
			return -1
		case earlierB:
			return 1
		}
		return a.Rotated.Compare(b.Rotated)
	})
	return files, nil
}

// parseRotated reads name as a rotated file of base: <stem><time><ext> or
// the earlier <base>.<n>.
func parseRotated(name, base, stem, ext string) (RotatedFile, bool) {
	if suffix, found := strings.CutPrefix(name, base+"."); found {
		if n, err := strconv.Atoi(suffix); err == nil && n >= 1 && strconv.Itoa(n) == suffix {
			return RotatedFile{Name: name, Number: n}, true
		}
	}
	middle, found := strings.CutPrefix(name, stem)
	if !found || !strings.HasSuffix(middle, ext) {
		return RotatedFile{}, false
	}
	at, err := time.Parse(rotatedLayout, strings.TrimSuffix(middle, ext))
	if err != nil {
		return RotatedFile{}, false
	}
	return RotatedFile{Name: name, Rotated: at}, true
}
