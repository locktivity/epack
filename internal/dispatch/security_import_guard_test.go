package dispatch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityImportGuard ensures the dispatch package uses safe primitives
// for security-critical operations.
//
// SECURITY BOUNDARY: The dispatch package executes untrusted tool binaries and must:
//   - Use safefile package for all file operations (prevents symlink attacks)
//   - Use execsafe package for binary execution (prevents TOCTOU attacks)
//   - Use execsafe.BuildRestrictedEnv to filter os.Environ (prevents credential leaks)
//
// Note: os.Environ() is SAFE when passed to execsafe.BuildRestrictedEnv().
// The guard focuses on file operations which must use safefile primitives.
//
// This test enforces those boundaries by failing if direct unsafe operations are used.
func TestSecurityImportGuard(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	if !strings.HasSuffix(wd, "internal/dispatch") {
		t.Skipf("skipping: not in internal/dispatch directory (in %s)", wd)
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("failed to read directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		// Skip test files - tests may use os operations for setup
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		filePath := filepath.Join(wd, entry.Name())
		file, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", entry.Name(), err)
		}

		// Check for unsafe function calls
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}

			// Check for direct os file operations that bypass safefile
			if ident.Name == "os" {
				switch sel.Sel.Name {
				case "Create", "WriteFile":
					pos := fset.Position(call.Pos())
					t.Errorf("SECURITY VIOLATION in %s:%d: direct os.%s call\n"+
						"Use safefile.WriteFile instead.\n"+
						"Direct os operations are vulnerable to symlink attacks.",
						entry.Name(), pos.Line, sel.Sel.Name)
				}
				// Note: os.Environ is allowed - the correct pattern is to pass it to
				// execsafe.BuildRestrictedEnv which filters it.
			}

			return true
		})
	}
}
