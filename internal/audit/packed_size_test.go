// The size a compressed file's header states is bounded before anything
// reads that many bytes.

package audit

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPackedRefusesBadSize(t *testing.T) {
	dir := t.TempDir()
	for _, size := range []string{"100000000000", "-1", "ten", "1e9"} {
		path := filepath.Join(dir, "audit-"+size+".log.gz")
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Comment = "first=2026-11-25T00:00:00Z last=2026-11-25T00:00:01Z sha256=deadbeef bytes=" + size
		if _, err := zw.Write(make([]byte, 1<<20)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		if packed, err := ReadPacked(path); err == nil {
			t.Errorf("bytes=%s: header accepted with size %d", size, packed.Bytes)
		}
		report, err := VerifyChain([]string{path}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if report.Records != 0 || !strings.Contains(strings.Join(report.Problems, "\n"), path) {
			t.Errorf("bytes=%s: verify read %d records, problems %v", size, report.Records, report.Problems)
		}
	}
}
