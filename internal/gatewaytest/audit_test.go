// Tests for reading active prefilled audit files up to their logical end.

package gatewaytest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLiveAuditSkipsZeroTail(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	line := `{"kind":"request.admitted","request_id":"req-1"}` + "\n"
	buf := make([]byte, 1<<20)
	copy(buf, line)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readLiveAudit(path)
	if err != nil {
		t.Fatalf("readLiveAudit: %v", err)
	}
	if string(got) != line {
		t.Fatalf("readLiveAudit returned %d bytes (%q), want %q", len(got), got, line)
	}
	events, err := ParseAudit(got, filepath.Base(path))
	if err != nil || len(events) != 1 || events[0]["request_id"] != "req-1" {
		t.Fatalf("ParseAudit: %v %v", events, err)
	}
}
