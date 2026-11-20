// Tests of the archiver: rotated files are compressed into the archive
// folder, recorded, and only then deleted; a failing archive folder falls
// back to the log folder; a crash at any step is finished at the next start;
// an eviction is recorded before its file is deleted; the reserve file is
// released and made again.

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// archiving opens a log under dir that archives into dir/archive.
func archiving(t *testing.T, s Settings) (*AuditLog, string, string) {
	dir := t.TempDir()
	path, archive := filepath.Join(dir, "audit.log"), filepath.Join(dir, "archive")
	s.Archive = archive
	return OpenAudit(path, s), path, archive
}

// stored lists the rotated files in dir.
func stored(t *testing.T, path, archive, dir string) []RotatedFile {
	t.Helper()
	files, err := RotatedFiles(path, archive)
	if err != nil {
		t.Fatal(err)
	}
	var in []RotatedFile
	for _, f := range files {
		if f.Dir == dir {
			in = append(in, f)
		}
	}
	return in
}

// logRecords reads the records of every file of the log.
func logRecords(t *testing.T, path, archive string) []Event {
	t.Helper()
	files, err := RotatedFiles(path, archive)
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	for _, f := range files {
		events = append(events, allRecords(t, f.Path())...)
	}
	return append(events, allRecords(t, path)...)
}

func digestOf(t *testing.T, r io.Reader) string {
	t.Helper()
	sum := sha256.New()
	if _, err := io.Copy(sum, r); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func TestArchiveCompressesAndRecords(t *testing.T) {
	a, path, archive := archiving(t, Settings{MaxBytes: 4 << 10, MaxFiles: 8, WhenFull: FullEvict})
	commitUntil(t, a, func() bool { return len(stored(t, path, archive, archive)) >= 2 })
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	archived := map[string]Event{}
	for _, e := range logRecords(t, path, archive) {
		if e.Kind == "audit.archived" {
			archived[e.File] = e
		}
	}
	for _, f := range stored(t, path, archive, archive) {
		header, err := ReadPacked(f.Path())
		if err != nil {
			t.Fatal(err)
		}
		reader, err := OpenRecords(f.Path())
		if err != nil {
			t.Fatal(err)
		}
		content := digestOf(t, reader)
		reader.Close()
		e, ok := archived[f.Plain()]
		if !ok || content != header.Digest || e.Digest != content || e.Archived != f.Bytes || e.Target != "archive" || e.First.IsZero() {
			t.Fatalf("%s: record %+v, header %+v, content %s", f.Name, e, header, content)
		}
		if fileExists(filepath.Join(filepath.Dir(path), f.Plain())) {
			t.Fatalf("%s: the original was kept", f.Plain())
		}
	}
	paths := []string{}
	files, _ := RotatedFiles(path, archive)
	for _, f := range files {
		paths = append(paths, f.Path())
	}
	report, err := VerifyChain(append(paths, path), nil)
	if err != nil || report.Unchained != 0 || len(report.Problems) != 0 || len(report.Missing) != 0 {
		t.Fatalf("verify over both folders: %+v (%v)", report, err)
	}
}

func TestArchiveFallsBackToLiveFolder(t *testing.T) {
	dir := t.TempDir()
	path, archive := filepath.Join(dir, "audit.log"), filepath.Join(dir, "archive")
	// A file where the folder should be: the archive cannot be written.
	if err := os.WriteFile(archive, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	a := OpenAudit(path, Settings{MaxBytes: 4 << 10, MaxFiles: 8, WhenFull: FullEvict, Storage: Storage{Archive: archive}})
	t.Cleanup(func() { a.Close(context.Background()) })
	packedLive := func() bool {
		for _, f := range stored(t, path, archive, dir) {
			if f.Packed {
				return true
			}
		}
		return false
	}
	commitUntil(t, a, packedLive)
	if state, _ := a.Archive(); state.Usable {
		t.Fatal("an unwritable archive is reported usable")
	}
	// Windows may hold the file a moment while the archiver probes it.
	waitFor(t, time.Now().Add(5*time.Second), "the placeholder removed", func() bool { return os.Remove(archive) == nil })
	a.archive.signal()
	waitFor(t, time.Now().Add(10*time.Second), "the compressed files to move", func() bool {
		return !packedLive() && len(stored(t, path, archive, archive)) > 0
	})
}

// A crash at each step of archiving leaves the original; the next start
// finishes it: a partial temporary file or a compressed copy without its
// record is replaced, the record written, then the original deleted.
func TestArchiveFinishesAfterCrash(t *testing.T) {
	for _, step := range []string{"none", "temporary", "renamed"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			path, archive := filepath.Join(dir, "audit.log"), filepath.Join(dir, "archive")
			name := filepath.Base(rotatedName(path, time.Now()))
			original := filepath.Join(dir, name)
			content := []byte(`{"time":"2026-11-20T01:00:00Z","kind":"request.forwarded"}` + "\n")
			if err := os.WriteFile(original, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(archive, 0o700); err != nil {
				t.Fatal(err)
			}
			switch step {
			case "temporary":
				os.WriteFile(filepath.Join(archive, name+".gz.tmp"), []byte("partial"), 0o600)
			case "renamed":
				if _, err := pack(original, archive); err != nil {
					t.Fatal(err)
				}
			}
			a := OpenAudit(path, Settings{MaxBytes: 1 << 20, MaxFiles: 8, WhenFull: FullEvict, Storage: Storage{Archive: archive}})
			waitFor(t, time.Now().Add(10*time.Second), "the original archived", func() bool { return !fileExists(original) })
			if err := a.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(content)
			header, err := ReadPacked(filepath.Join(archive, name+".gz"))
			if err != nil || header.Digest != hex.EncodeToString(sum[:]) || fileExists(filepath.Join(archive, name+".gz.tmp")) {
				t.Fatalf("archived copy %+v (%v)", header, err)
			}
			recorded := false
			for _, e := range allRecords(t, path) {
				recorded = recorded || (e.Kind == "audit.archived" && e.File == name)
			}
			if !recorded {
				t.Fatal("no audit.archived record")
			}
		})
	}
}

// Below the free-space threshold (every disk is, at 100 %) the oldest files
// are evicted, each recorded with the disk-pressure reason; files holding
// earlier eviction records are evicted too, so at least one record remains.
func TestPressureEvictsOldest(t *testing.T) {
	if _, err := diskOf(t.TempDir()); err != nil || runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("free space is read on Linux and Windows only")
	}
	a, path, archive := archiving(t, Settings{MaxBytes: 4 << 10, MaxFiles: 8, WhenFull: FullEvict, Storage: Storage{MinFree: 100}})
	commitUntil(t, a, func() bool { return len(stored(t, path, archive, archive)) >= 1 || a.archive.pressure.Load() >= 1 })
	// The archiver evicts on its own pace; wait for it rather than commit more.
	waitFor(t, time.Now().Add(10*time.Second), "a disk-pressure eviction", func() bool { return a.archive.pressure.Load() >= 1 })
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	evicted := 0
	for _, e := range logRecords(t, path, archive) {
		if e.Kind == "audit.evicted" && e.Reason == evictPressure && e.Digest != "" {
			evicted++
		}
	}
	if evicted < 1 {
		t.Fatal("no disk-pressure eviction record")
	}
}

func TestReserveReleasedAndRemade(t *testing.T) {
	// Not parallel: the pause is a package value, set before the log opens.
	pause := reservePause
	reservePause = 0
	t.Cleanup(func() { reservePause = pause })
	a, path, _ := archiving(t, Settings{MaxBytes: 1 << 20, MaxFiles: 8, WhenFull: FullEvict, Storage: Storage{Reserve: 64 << 10}})
	t.Cleanup(func() { a.Close(context.Background()) })
	reserve := reserveName(path)
	waitFor(t, time.Now().Add(10*time.Second), "the reserve", func() bool { return fileExists(reserve) })
	if info, err := os.Stat(reserve); err != nil || info.Size() != 64<<10 {
		t.Fatalf("reserve %v (%v)", info, err)
	}
	if !a.releaseReserve() || fileExists(reserve) || a.releaseReserve() {
		t.Fatal("the reserve was not released exactly once")
	}
	waitFor(t, time.Now().Add(10*time.Second), "the reserve made again", func() bool { return fileExists(reserve) })
}
