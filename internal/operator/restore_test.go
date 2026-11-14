// Restore refuses a live database path with leftover companion files.

package operator

import (
	"os"
	"path/filepath"
	"testing"
)

// A rollback journal left beside the live path would be rolled back into
// the promoted database on its first open, so the restore is refused.
func TestRestoreRefusesJournal(t *testing.T) {
	live := filepath.Join(t.TempDir(), "gateway.db")
	if err := os.WriteFile(live+"-journal", []byte("journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkLive(live, "installation"); err == nil {
		t.Fatal("a leftover rollback journal was accepted")
	}
}
