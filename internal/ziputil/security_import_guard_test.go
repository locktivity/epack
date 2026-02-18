package ziputil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityImportGuard ensures that ZIP operations outside this package
// use SafeReader for security checks.
//
// SECURITY BOUNDARY: The ziputil package provides SafeReader which enforces:
//   - Entry count limits (DoS prevention)
//   - Compression ratio limits (zip bomb prevention)
//   - Path safety (traversal, encoding, reserved names)
//   - Windows path collision detection
//
// Direct use of zip.OpenReader or zip.NewReader in security-sensitive packages
// bypasses these protections. This test ensures such usage only occurs in:
//   - Test files (*_test.go)
//   - This package (internal/ziputil/)
//   - Files with explicit SafeReader wrapping (pack/pack.go uses OpenReader but wraps with SafeReader)
//
// If this test fails, either:
// 1. Use ziputil.NewSafeReader() instead of direct zip operations
// 2. Add an exemption with a security justification comment
func TestSecurityImportGuard(t *testing.T) {
	// Packages that must use SafeReader (not direct zip operations)
	// Note: pack/pack.go is allowed to use zip.OpenReader because it immediately
	// wraps the result with NewSafeReaderFromZip - this is the canonical entry point.
	securitySensitivePackages := []string{
		"pack/builder",
		"pack/extract",
		"internal/component/sync",
	}

	// Find repo root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	repoRoot := findRepoRoot(wd)
	if repoRoot == "" {
		t.Skip("could not find repo root")
	}

	for _, pkg := range securitySensitivePackages {
		pkgPath := filepath.Join(repoRoot, pkg)
		if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
			continue
		}

		entries, err := os.ReadDir(pkgPath)
		if err != nil {
			t.Fatalf("failed to read %s: %v", pkgPath, err)
		}

		fset := token.NewFileSet()
		for _, entry := range entries {
			// Skip directories and non-Go files
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			// Skip test files - they can use direct zip operations for test setup
			if strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}

			filePath := filepath.Join(pkgPath, entry.Name())
			file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", filePath, err)
			}

			// Check for direct zip function calls
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

				// Check for zip.OpenReader or zip.NewReader
				if ident.Name == "zip" {
					if sel.Sel.Name == "OpenReader" || sel.Sel.Name == "NewReader" {
						pos := fset.Position(call.Pos())
						t.Errorf("SECURITY VIOLATION in %s/%s:%d: direct zip.%s call\n"+
							"Use ziputil.NewSafeReader() or ziputil.NewSafeReaderFromZip() instead.\n"+
							"SafeReader enforces entry limits, compression ratio checks, and path validation.",
							pkg, entry.Name(), pos.Line, sel.Sel.Name)
					}
				}

				return true
			})
		}
	}
}

// findRepoRoot walks up from dir looking for go.mod
func findRepoRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
