package sync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityImportGuard ensures the sync package uses safe primitives
// for security-critical operations.
//
// SECURITY BOUNDARY: The sync package downloads and installs untrusted binaries.
// It must:
//   - Use safefile package for all file operations (prevents symlink attacks)
//   - Not expose os.Environ to downloaded binaries
//   - Never import internal/catalog (catalog is for display only, not execution decisions)
//
// Note: os.MkdirAll is allowed in sync package for creating install directories
// that don't involve untrusted paths. The critical safety comes from:
//   - Verifying signatures before trusting content
//   - Using safefile for operations involving user-controlled paths
//
// This test enforces minimal security boundaries.
func TestSecurityImportGuard(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	if !strings.HasSuffix(wd, "internal/component/sync") {
		t.Skipf("skipping: not in internal/component/sync directory (in %s)", wd)
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
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		filePath := filepath.Join(wd, entry.Name())
		file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", entry.Name(), err)
		}

		// Check for forbidden imports
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(importPath, "internal/catalog") {
				t.Errorf("SECURITY VIOLATION: %s imports %s\n"+
					"The sync package must NOT import internal/catalog.\n"+
					"Catalog data is for discovery/display only.\n"+
					"Sync decisions must come exclusively from the lockfile.",
					entry.Name(), importPath)
			}
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

			if ident.Name == "os" && sel.Sel.Name == "Environ" {
				pos := fset.Position(call.Pos())
				t.Errorf("SECURITY VIOLATION in %s:%d: direct os.Environ call\n"+
					"Use execsafe.BuildRestrictedEnv instead.",
					entry.Name(), pos.Line)
			}

			// exec.Command shouldn't be needed in sync - it downloads, not executes
			if ident.Name == "exec" && sel.Sel.Name == "Command" {
				pos := fset.Position(call.Pos())
				t.Errorf("SECURITY VIOLATION in %s:%d: direct exec.Command call\n"+
					"The sync package should not execute binaries - only download and verify.",
					entry.Name(), pos.Line)
			}

			return true
		})
	}
}
