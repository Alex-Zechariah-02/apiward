// Permission use with rotated-file summaries answers exactly as a full read,
// and the active file's kept prefix is read again only when it may have changed.

package monitor

import (
	"fmt"
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
		files, _, err := LogFiles(active, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, budget := range budgets {
			plain, err := (&Summaries{}).PermitUse(t.Context(), files, budget)
			if err != nil {
				t.Fatal(err)
			}
			for _, call := range []string{"first", "second"} {
				cached, err := cache.PermitUse(t.Context(), files, budget)
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

// requestLine is a forwarded request record of boot carrying role.
func requestLine(boot string, n int, role string) string {
	return fmt.Sprintf(`{"schema":8,"event_id":"%s-%d","time":"2026-11-02T09:00:%02dZ","kind":"request.forwarded","request_id":"r%d","stage":"FORWARD","decision":"forwarded","status":200,"operation":"read","roles":[%q]}`+"\n", boot, n, n%60, n, role)
}

// The active file's records already read are kept: an append is read alone,
// so a rewritten earlier record is not seen, until a new gateway start
// writes to the file, or it gets shorter, when the whole file is read again.
func TestPermitUseActivePrefix(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.log")
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(active, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(cache *Summaries) LogUse {
		t.Helper()
		use, err := cache.PermitUse(t.Context(), []string{filepath.Join(dir, "audit.log")}, ExportScan)
		if err != nil {
			t.Fatal(err)
		}
		return use
	}
	first := requestLine("a", 1, "OLD") + requestLine("a", 2, "OLD")
	write(first)
	var cache Summaries
	read(&cache)
	// Same length, same first record: only a re-read would notice.
	rewritten := requestLine("a", 1, "OLD") + requestLine("a", 2, "NEW")
	write(rewritten + requestLine("a", 3, "TAIL"))
	use := read(&cache)
	if use.requests != 3 || use.used[[2]string{"NEW", "read"}] || !use.used[[2]string{"TAIL", "read"}] {
		t.Fatalf("an append read the kept prefix again: %+v", use)
	}
	write(rewritten + requestLine("a", 3, "TAIL") + requestLine("b", 1, "RESTART"))
	if use := read(&cache); use.requests != 4 || !use.used[[2]string{"NEW", "read"}] || !use.used[[2]string{"RESTART", "read"}] {
		t.Fatalf("a new start did not read the whole file: %+v", use)
	}
	write(requestLine("a", 1, "OLD"))
	if use, plain := read(&cache), read(&Summaries{}); !reflect.DeepEqual(use, plain) {
		t.Fatalf("a shorter file: %+v, a full read %+v", use, plain)
	}
}
