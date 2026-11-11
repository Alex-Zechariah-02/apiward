//go:build embedui

// The release build carries the whole Dashboard build.

package adminui

import (
	"io/fs"
	"regexp"
	"testing"
)

// TestEmbeddedFiles proves the embedui build embeds the copied build: its
// page and every asset the page names, as the file or as its gzip copy.
func TestEmbeddedFiles(t *testing.T) {
	page, err := fs.ReadFile(Files, "index.html")
	if err != nil {
		t.Fatalf("no embedded index.html: %v", err)
	}
	assets := regexp.MustCompile(`(?:src|href)="/(assets/[^"]+)"`).FindAllSubmatch(page, -1)
	if len(assets) == 0 {
		t.Fatal("the embedded page names no assets")
	}
	for _, asset := range assets {
		name := string(asset[1])
		if _, err := fs.Stat(Files, name); err == nil {
			continue
		}
		if _, err := fs.Stat(Files, name+".gz"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
