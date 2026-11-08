// The Admin API's access to the database: reads only.

package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"testing"
)

// openers are the store's names that hold or open a writable database.
var openers = []string{"DB", "Adopt", "Connect", "CreatePrivate", "CreateStore", "LockDeployment", "OpenForMigration", "OpenStore", "ApplyMigrations"}

// The Admin API is given store.Reads, which has no write method; naming the
// database type (to assert to it) or an opener would give it a write path.
func TestReadsOnlyStore(t *testing.T) {
	files, _ := filepath.Glob("*.go")
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
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "store" && slices.Contains(openers, sel.Sel.Name) {
				t.Errorf("%s names store.%s", name, sel.Sel.Name)
			}
			return true
		})
	}
}
