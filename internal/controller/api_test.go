// The controller's exported surface: the operations it allows other packages,
// and Publish confined to tests and the fault-injection build.

package controller

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// exported is every exported identifier of the package: changes, reads,
// lifecycle and settings. Each change goes through the lock and the durable
// transition path; nothing here publishes a generation or commits a
// transition on its own, except Publish (see TestPublishOnlyInTests).
var exported = []string{
	"CandidateGeneration", "Change", "Config", "Config.Check", "Controller",
	"Controller.Activate", "Controller.Addresses", "Controller.Admission", "Controller.Audit",
	"Controller.BeginStop", "Controller.Block", "Controller.BlockAddress", "Controller.Blocked",
	"Controller.Capture", "Controller.ChangePassword", "Controller.CreateOverride", "Controller.Current",
	"Controller.Enrol", "Controller.EstablishBase", "Controller.Expired", "Controller.Gauges", "Controller.Network",
	"Controller.Observations", "Controller.Open", "Controller.Publish", "Controller.Reads",
	"Controller.ReloadKeys", "Controller.Resolve", "Controller.RevokeOverride", "Controller.Sessions",
	"Controller.Settings", "Controller.StageCandidate", "Controller.Start", "Controller.State",
	"Controller.Stop", "Controller.StopWithin", "Controller.Unblock", "Controller.UnblockAddress",
	"Controller.ValidateOverride", "Controller.Verifier", "Controller.WithdrawCandidate",
	"DefaultAuditWait", "DefaultIdle", "DefaultIgnoredReads", "DefaultLifetime", "MaxAuditBytes", "MaxAuditFiles",
	"MaxSession", "MinAuditBytes", "MinSession", "Outcome", "OverrideRequest", "Prepare", "ShutdownWait",
}

// A new exported name is a new way into the authority, so it is listed here
// on purpose or not at all.
func TestControllerAPI(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	var got []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			got = append(got, exportedNames(decl)...)
		}
	}
	slices.Sort(got)
	if want := slices.Sorted(slices.Values(exported)); !slices.Equal(got, want) {
		t.Fatalf("exported identifiers\n got %v\nwant %v", got, want)
	}
}

func exportedNames(decl ast.Decl) []string {
	var names []string
	switch d := decl.(type) {
	case *ast.FuncDecl:
		name := d.Name.Name
		if d.Recv != nil {
			receiver := d.Recv.List[0].Type
			if star, ok := receiver.(*ast.StarExpr); ok {
				receiver = star.X
			}
			name = receiver.(*ast.Ident).Name + "." + name
		}
		if ast.IsExported(d.Name.Name) {
			names = append(names, name)
		}
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				if s.Name.IsExported() {
					names = append(names, s.Name.Name)
				}
			case *ast.ValueSpec:
				for _, n := range s.Names {
					if n.IsExported() {
						names = append(names, n.Name)
					}
				}
			}
		}
	}
	return names
}

// Publish installs a whole policy without Confirmed Policy Activation, so no
// production source of the module may call it: only tests and files built
// with the faultinject tag.
func TestPublishOnlyInTests(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == "node_modules" || strings.HasPrefix(entry.Name(), ".")) && path != root {
			return filepath.SkipDir
		}
		// A folder with its own go.mod is another module, not this one's source.
		if _, err := os.Stat(filepath.Join(path, "go.mod")); entry.IsDir() && path != root && err == nil {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil || !production(file) {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Publish" {
					t.Errorf("%s calls Publish outside a test or faultinject build", path)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// production reports whether file is built without the faultinject tag.
func production(file *ast.File) bool {
	for _, group := range file.Comments {
		if group.Pos() > file.Package {
			break
		}
		for _, line := range group.List {
			if expr, err := constraint.Parse(line.Text); err == nil {
				return expr.Eval(func(tag string) bool { return tag != "faultinject" })
			}
		}
	}
	return true
}
