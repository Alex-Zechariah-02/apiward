// The Admin API's access to the database: reads only.

package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The Admin API is given store.Reads, which has no write method; naming the
// database type (to assert to it) or a function that opens or changes the
// database would give it a write path. The names are derived from the store
// package, so a new opener is covered without editing this test.
func TestReadsOnlyStore(t *testing.T) {
	writers := storeWriters(t)
	for _, known := range []string{"DB", "OpenStore", "CreateStore", "Adopt", "LockDeployment"} {
		if !slices.Contains(writers, known) {
			t.Fatalf("derived write names %v miss %s", writers, known)
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no Admin API files to check (%v)", err)
	}
	for _, name := range files {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "store" && slices.Contains(writers, sel.Sel.Name) {
				t.Errorf("%s names store.%s", name, sel.Sel.Name)
			}
			return true
		})
	}
}

// storeWriters lists the store names that hold or open a writable database:
// the DB type and every exported function whose signature names DB, a
// database/sql handle or an open file, or whose body opens one.
func storeWriters(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "store", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no store files to read (%v)", err)
	}
	writers := []string{"DB"}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && fn.Name.IsExported() && (handlesDatabase(fn.Type) || (fn.Body != nil && opensFile(fn.Body))) {
				writers = append(writers, fn.Name.Name)
			}
		}
	}
	return writers
}

// handlesDatabase reports whether a signature names DB, a database/sql
// handle (not its value types such as sql.NullInt64) or os.File.
func handlesDatabase(signature ast.Node) bool {
	found := false
	ast.Inspect(signature, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			pkg, _ := n.X.(*ast.Ident)
			found = found || pkg != nil && (pkg.Name == "sql" && slices.Contains([]string{"DB", "Tx", "Conn", "Rows", "Stmt"}, n.Sel.Name) || pkg.Name == "os" && n.Sel.Name == "File")
			return false
		case *ast.Ident:
			found = found || n.Name == "DB"
		}
		return !found
	})
	return found
}

// opensFile reports whether a body creates or opens a file or a database.
func opensFile(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			pkg, _ := sel.X.(*ast.Ident)
			found = found || pkg != nil && (pkg.Name == "os" && slices.Contains([]string{"OpenFile", "Create", "WriteFile"}, sel.Sel.Name) || pkg.Name == "sql" && sel.Sel.Name == "Open")
		}
		return !found
	})
	return found
}
