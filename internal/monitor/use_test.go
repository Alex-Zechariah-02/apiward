// Permission use with rotated-file summaries answers exactly as a full read.

package monitor

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPermitUseSummaries(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	// Rotated files span several read windows, so a full read takes more
	// budget than the file's size.
	writeAuditFile(t, active+".2", 1, 30000, "")
	writeAuditFile(t, active+".1", 30001, 60000, "")
	writeAuditFile(t, active, 60001, 60004, "")
	size := func(name string) int64 {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return info.Size()
	}
	total := size("audit.log") + size("audit.log.1") + size("audit.log.2")
	// Whole log; cuts inside the oldest file, at its middle and just before
	// its start; a cut inside the active file.
	budgets := []int64{ExportScan, total - size("audit.log.2")/2, total - 100, 300}
	var cache Summaries
	compare := func(step string) {
		t.Helper()
		files, _, err := LogFiles(active, 8)
		if err != nil {
			t.Fatal(err)
		}
		for _, budget := range budgets {
			plain, err := (&Summaries{}).PermitUse(dir, files, budget)
			if err != nil {
				t.Fatal(err)
			}
			for _, call := range []string{"first", "second"} {
				cached, err := cache.PermitUse(dir, files, budget)
				if err != nil || !reflect.DeepEqual(cached, plain) {
					t.Errorf("%s, budget %d, %s call: %+v, uncached %+v (%v)", step, budget, call, cached, plain, err)
				}
			}
		}
	}
	compare("three files")
	if len(cache.files) != 2 {
		t.Fatalf("summaries kept for %d files, want the 2 rotated ones", len(cache.files))
	}
	if entry := cache.files["audit.log.1"]; entry.cost <= size("audit.log.1") {
		t.Errorf("a multi-window file's summary charges %d, its size is %d", entry.cost, size("audit.log.1"))
	}
	// A changed rotated file is read again; a removed one loses its summary.
	writeAuditFile(t, active+".1", 30001, 30500, "")
	compare("changed file")
	if err := os.Remove(active + ".2"); err != nil {
		t.Fatal(err)
	}
	compare("removed file")
	if _, ok := cache.files["audit.log.2"]; ok {
		t.Error("the removed file keeps its summary")
	}
}
