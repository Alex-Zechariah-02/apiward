// Layering of the internal packages (none imports a package above it), the
// internal packages each public package may reach, and the boundary between
// the gateway and the Fetch example module.

package gateway

import (
	"errors"
	"go/build"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// layers lists, for each internal package, the internal packages it may import.
var layers = map[string][]string{
	"fault":       nil,
	"adminui":     nil,
	"policy":      nil,
	"compile":     {"fault", "policy"},
	"forward":     {"policy", "compile"},
	"store":       {"fault", "policy"},
	"audit":       {"fault"},
	"session":     nil,
	"connections": nil,
	"monitor":     {"policy", "compile", "audit"},
	"issuertest":  nil,
	"storetest":   {"policy", "store"},
	"pipeline":    {"fault", "policy", "compile", "forward", "store", "audit", "monitor"},
	"controller":  {"fault", "policy", "compile", "forward", "store", "audit", "session", "monitor", "pipeline", "connections"},
	"admin":       {"policy", "compile", "store", "audit", "session", "monitor", "pipeline", "controller"},
	"operator":    {"fault", "policy", "store", "audit", "session"},
	"gatewaytest": {"policy", "store", "audit", "session", "pipeline", "controller", "issuertest"},
	"openapi":     {"policy", "compile"},
	"gateway":     {"fault", "policy", "compile", "forward", "store", "audit", "session", "monitor", "pipeline", "controller", "admin", "operator", "adminui", "connections"},
	// integration tests reach the gateway only through its processes.
	"integration": {"policy", "compile", "store", "audit", "session", "monitor", "pipeline", "controller"},
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
var unlayered = []string{"demoports", "testfixture"}

// support packages exist for tests: any package's tests may import them,
// production code never.
var support = []string{"issuertest", "storetest", "gatewaytest"}

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
		// A folder of data, such as a copied web build, holds no package.
		if !hasGoFiles(path) {
			return nil
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

// TestNoExampleImports keeps the gateway apart from its examples: no gateway
// package imports the Fetch application or a package under examples/. (Go's
// internal rule already keeps Fetch out of the gateway's internal packages.)
func TestNoExampleImports(t *testing.T) {
	root := filepath.Join("..", "..")
	module := modulePath(t, root)
	banned := []string{module + "/examples/", "github.com/Alex-Zechariah-02/fetch"}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		switch name := d.Name(); {
		case name == "node_modules", name == "testdata", name == "dashboard", path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")):
			return filepath.SkipDir
		}
		// A folder with its own go.mod is another module, not gateway code.
		if _, err := os.Stat(filepath.Join(path, "go.mod")); path != root && err == nil {
			return filepath.SkipDir
		}
		for _, tags := range [][]string{nil, {"faultinject"}} {
			ctx := build.Default
			ctx.BuildTags = tags
			pkg, err := ctx.ImportDir(path, 0)
			var none *build.NoGoError
			if errors.As(err, &none) {
				return nil
			}
			if err != nil {
				return err
			}
			for _, imp := range slices.Concat(pkg.Imports, pkg.TestImports, pkg.XTestImports) {
				if slices.ContainsFunc(banned, func(prefix string) bool { return strings.HasPrefix(imp, prefix) }) {
					t.Errorf("%s imports an example: %s", filepath.ToSlash(path), imp)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// hasGoFiles reports whether dir directly holds a Go file.
func hasGoFiles(dir string) bool {
	entries, _ := os.ReadDir(dir)
	return slices.ContainsFunc(entries, func(e os.DirEntry) bool { return !e.IsDir() && strings.HasSuffix(e.Name(), ".go") })
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
