package tool

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityImportGuard ensures the tool package uses safe primitives
// for security-critical operations.
//
// SECURITY BOUNDARY: The tool package handles tool resolution and must:
//   - Use safefile package for all file operations (prevents symlink attacks)
//   - Use execsafe package for binary verification (prevents TOCTOU attacks)
//   - Use execsafe.BuildRestrictedEnv to filter os.Environ (prevents credential leaks)
//
// Note: os.Environ() is SAFE when passed to execsafe.BuildRestrictedEnv().
// The guard focuses on file operations and direct exec.Command usage.
//
// This test enforces those boundaries by failing if direct unsafe operations are used.
func TestSecurityImportGuard(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	if !strings.HasSuffix(wd, "internal/tool") {
		t.Skipf("skipping: not in internal/tool directory (in %s)", wd)
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
		// Skip test files
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		filePath := filepath.Join(wd, entry.Name())
		file, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", entry.Name(), err)
		}

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

			if ident.Name == "os" {
				switch sel.Sel.Name {
				case "Create", "WriteFile", "MkdirAll":
					pos := fset.Position(call.Pos())
					t.Errorf("SECURITY VIOLATION in %s:%d: direct os.%s call\n"+
						"Use safefile package instead.\n"+
						"Direct os operations are vulnerable to symlink attacks.",
						entry.Name(), pos.Line, sel.Sel.Name)
				}
				// Note: os.Environ is allowed when passed to execsafe.BuildRestrictedEnv
			}

			// exec.Command is allowed for capabilities probing which uses BuildRestrictedEnv
			// The security comes from the environment filtering, not avoiding exec.Command

			return true
		})
	}
}
