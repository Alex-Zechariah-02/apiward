// Layering of the internal packages (none imports a package above it) and
// the internal packages each public package may reach.

package gateway

import (
	"go/build"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// layers lists, for each internal package, the internal packages it may import.
var layers = map[string][]string{
	"fault":      nil,
	"policy":     nil,
	"compile":    {"fault", "policy"},
	"forward":    {"compile"},
	"store":      {"fault", "policy"},
	"audit":      {"fault"},
	"session":    nil,
	"monitor":    {"policy", "compile", "audit"},
	"testissuer": nil,
	"pipeline":   {"fault", "policy", "compile", "forward", "store", "audit", "monitor"},
	"controller": {"fault", "policy", "compile", "store", "audit", "session", "monitor", "pipeline"},
	"openapi":    {"policy", "compile"},
	"gateway":    {"fault", "policy", "compile", "forward", "store", "audit", "session", "monitor", "pipeline", "controller"},
}

// exposed lists, for each package outside internal/, the internal packages its
// non-test code may import: a public package reaches the core only through
// these, never the store, audit writer or forwarder directly.
var exposed = map[string][]string{
	".":              {"gateway"},
	"policy":         {"policy", "compile"},
	"examples/embed": nil,
	"module":         nil,
}

// unlayered packages are not part of the gateway's layering.
var unlayered = []string{"demoports", "services", "services/testfixture"}

// support packages exist for tests: any package's tests may import them,
// production code never.
var support = []string{"testissuer"}

func TestPackageLayers(t *testing.T) {
	root := filepath.Join("..", "..")
	module := modulePath(t, root)
	var found []string
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || path == filepath.Join(root, "internal") {
			return err
		}
		// The go tool ignores these directories, so they hold no package.
		if name := d.Name(); name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(filepath.Join(root, "internal"), path)
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range found {
		allowed, listed := layers[name]
		if !listed {
			if !slices.Contains(unlayered, name) {
				t.Errorf("internal/%s is not in the layer table", name)
			}
			continue
		}
		for _, tags := range [][]string{nil, {"faultinject"}} {
			ctx := build.Default
			ctx.BuildTags = tags
			pkg, err := ctx.ImportDir(filepath.Join(root, "internal", filepath.FromSlash(name)), 0)
			if err != nil {
				t.Fatalf("internal/%s: %v", name, err)
			}
			for _, imp := range pkg.Imports {
				dep, ok := strings.CutPrefix(imp, module+"/internal/")
				if ok && !slices.Contains(allowed, dep) && !slices.Contains(unlayered, dep) {
					t.Errorf("internal/%s imports internal/%s (tags %v)", name, dep, tags)
				}
			}
			for _, imp := range pkg.TestImports {
				dep, ok := strings.CutPrefix(imp, module+"/internal/")
				if ok && !slices.Contains(allowed, dep) && !slices.Contains(unlayered, dep) && !slices.Contains(support, dep) {
					t.Errorf("internal/%s tests import internal/%s (tags %v)", name, dep, tags)
				}
			}
		}
	}
}

func TestPublicImports(t *testing.T) {
	root := filepath.Join("..", "..")
	module := modulePath(t, root)
	for name, allowed := range exposed {
		pkg, err := build.Default.ImportDir(filepath.Join(root, filepath.FromSlash(name)), 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, imp := range pkg.Imports {
			dep, ok := strings.CutPrefix(imp, module+"/internal/")
			if ok && !slices.Contains(allowed, dep) {
				t.Errorf("%s imports internal/%s", name, dep)
			}
		}
	}
}

// modulePath reads the module path from go.mod.
func modulePath(t *testing.T, root string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatal("go.mod has no module line")
	return ""
}
