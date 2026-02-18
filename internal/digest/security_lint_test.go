package digest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoVariableTimeComparison ensures digest comparisons use constant-time methods.
//
// SECURITY: Digest comparisons must use Digest.Equal() which wraps subtle.ConstantTimeCompare.
// Variable-time string comparisons (==, !=) leak timing information that can be used
// to recover digest values byte-by-byte.
//
// This test flags patterns like:
//   - digest.String() == other.String()
//   - d1.String() == d2.String()
//   - someDigest == expectedDigest (string comparison)
//
// These should be replaced with:
//   - d1.Equal(d2)
//   - digest.Equal(d1, d2)
func TestNoVariableTimeComparison(t *testing.T) {
	// Packages that handle digest comparison
	packagesToCheck := []string{
		"pack",
		"pack/verify",
		"pack/builder",
		"internal/dispatch",
		"internal/collector",
		"internal/component/sync",
		"internal/component/sigstore",
	}

	repoRoot := findRepoRoot(t)
	if repoRoot == "" {
		t.Skip("could not find repo root")
	}

	for _, pkg := range packagesToCheck {
		pkgPath := filepath.Join(repoRoot, pkg)
		if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
			continue
		}

		entries, err := os.ReadDir(pkgPath)
		if err != nil {
			continue
		}

		fset := token.NewFileSet()
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			// Skip test files - they may use string comparison for test setup
			if strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}

			filePath := filepath.Join(pkgPath, entry.Name())
			file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
			if err != nil {
				continue
			}

			// Look for binary expressions that compare strings
			ast.Inspect(file, func(n ast.Node) bool {
				binExpr, ok := n.(*ast.BinaryExpr)
				if !ok {
					return true
				}

				// Only check == and != operations
				if binExpr.Op.String() != "==" && binExpr.Op.String() != "!=" {
					return true
				}

				// Check if either side is a .String() call on something that looks like a digest
				leftIsDigestString := isDigestStringCall(binExpr.X)
				rightIsDigestString := isDigestStringCall(binExpr.Y)

				if leftIsDigestString || rightIsDigestString {
					pos := fset.Position(binExpr.Pos())
					t.Errorf("SECURITY: %s/%s:%d potential variable-time digest comparison\n"+
						"Use Digest.Equal() for constant-time comparison instead of string %s.\n"+
						"Variable-time comparison leaks timing information.",
						pkg, entry.Name(), pos.Line, binExpr.Op.String())
				}

				return true
			})
		}
	}
}

// isDigestStringCall checks if an expression is a .String() call on a digest-like variable.
func isDigestStringCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Check if calling .String()
	if sel.Sel.Name != "String" {
		return false
	}

	// Check if the receiver looks like a digest (contains "digest" or "Digest" in name)
	ident, ok := sel.X.(*ast.Ident)
	if ok {
		name := strings.ToLower(ident.Name)
		return strings.Contains(name, "digest")
	}

	return false
}

func findRepoRoot(t *testing.T) string {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	dir := wd
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
