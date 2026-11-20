// Tests of compressed files: a reader at any offset returns the original
// content across block boundaries, and verification reports an archived
// file whose content was changed and one that is missing.

package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPackedReadsAtOffsets(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "audit-2026-11-20T01-00-00.000.log")
	var content bytes.Buffer
	for i := 0; content.Len() < 3*blockSize+blockSize/2; i++ {
		fmt.Fprintf(&content, `{"time":"2026-11-20T01:00:%02d.%06dZ","seq":%d,"kind":"request.forwarded","pad":"%d"}`+"\n", i%60, i, i, rand.Uint64())
	}
	if err := os.WriteFile(src, content.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := pack(src, dir)
	if err != nil {
		t.Fatal(err)
	}
	gz := src + packedSuffix
	reader, err := OpenLog(gz)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if end, err := reader.End(); err != nil || end != int64(content.Len()) || e.Bytes != end {
		t.Fatalf("end %d, described %d, want %d (%v)", end, e.Bytes, content.Len(), err)
	}
	for _, at := range []int64{0, blockSize - 7, blockSize, 2*blockSize - 1, int64(content.Len()) - 100} {
		got := make([]byte, 64)
		n, err := reader.ReadAt(got, at)
		want := content.Bytes()[at:min(at+64, int64(content.Len()))]
		if (err != nil && err != io.EOF) || !bytes.Equal(got[:n], want) {
			t.Fatalf("at %d: %q, want %q (%v)", at, got[:n], want, err)
		}
	}
	// Any gzip reader reads the members as one stream.
	file, _ := os.Open(gz)
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	if all, err := io.ReadAll(zr); err != nil || !bytes.Equal(all, content.Bytes()) {
		t.Fatalf("stream read differs (%v)", err)
	}
}

func TestVerifyFindsChangedAndMissingArchives(t *testing.T) {
	a, path, archive := archiving(t, Settings{MaxBytes: 4 << 10, MaxFiles: 8, WhenFull: FullEvict})
	commitUntil(t, a, func() bool { return len(stored(t, path, archive, archive)) >= 3 })
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	files := stored(t, path, archive, archive)
	changed := files[1].Path()
	// Rewrite the content with its header kept: one record altered.
	reader, _ := OpenRecords(changed)
	data, _ := io.ReadAll(reader)
	reader.Close()
	header, _ := ReadPacked(changed)
	altered := strings.Replace(string(data), "request.admitted", "request.admittex", 1)
	var out bytes.Buffer
	if _, err := writeBlocks(&out, strings.NewReader(altered), gzip.Header{Comment: headerComment(Event{First: header.First, Last: header.Last, Digest: header.Digest, Bytes: header.Bytes}), ModTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(changed, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{files[0].Path(), changed}
	for _, f := range files[3:] {
		paths = append(paths, f.Path())
	}
	all, _ := RotatedFiles(path, archive)
	for _, f := range all {
		if f.Dir != archive {
			paths = append(paths, f.Path())
		}
	}
	report, err := VerifyChain(append(paths, path), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, problem := range report.Problems {
		found = found || strings.Contains(problem, "does not match the SHA-256")
	}
	if !found || len(report.Missing) != 1 || report.Missing[0] != files[2].Plain() || report.Valid() {
		t.Fatalf("report %+v: want the changed file and %s missing", report, files[2].Plain())
	}
}
