// The settings file is read only as a regular file, directly or through a
// link (a container's mounted configuration).

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsFileRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	valid := string(configDocument(t, dir, nil))
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNativeConfig(filepath.Dir(path)); err == nil || !strings.Contains(err.Error(), "must name a regular file") {
		t.Errorf("a directory: got %v", err)
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if os.Symlink(path, link) == nil {
		if _, err := readNativeConfig(link); err != nil {
			t.Errorf("a link to a regular file: %v", err)
		}
	}
}
