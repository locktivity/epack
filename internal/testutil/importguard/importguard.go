// Package importguard provides test helpers for enforcing import boundaries.
//
// Import guards are AST-based tests that enforce security boundaries by
// detecting forbidden imports or risky function calls at test time.
//
// Example usage:
//
//	func TestNoForbiddenImports(t *testing.T) {
//	    importguard.AssertNoImport(t, "internal/catalog",
//	        "Catalog data is for discovery only")
//	}
package importguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AssertNoImport fails the test if any non-test Go file in the current package
// imports a path containing the forbidden string.
//
// Use this to enforce security boundaries where a package must not depend on
// another package (e.g., execution packages must not import catalog).
func AssertNoImport(t *testing.T, forbiddenImport, reason string) {
	t.Helper()
	AssertNoImports(t, []string{forbiddenImport}, reason)
}

// AssertNoImports fails the test if any non-test Go file in the current package
// imports a path containing any of the forbidden strings.
//
// Use this when multiple import boundaries need to be enforced.
func AssertNoImports(t *testing.T, forbiddenImports []string, reason string) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}

	fset := token.NewFileSet()

	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("reading directory: %v", err)
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
		file, err := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), err)
		}

		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			for _, forbidden := range forbiddenImports {
				if strings.Contains(importPath, forbidden) {
					t.Errorf("SECURITY VIOLATION: %s imports %s\n%s",
						entry.Name(), importPath, reason)
				}
			}
		}
	}
}

// RiskyCall defines a package and set of function names that are risky to use.
type RiskyCall struct {
	Package   string   // Package identifier (e.g., "os")
	Functions []string // Function names to flag (e.g., "Create", "WriteFile")
	Reason    string   // Why this is risky
}

// AssertNoRiskyCalls fails the test if any non-test Go file in the current
// package calls any of the specified risky functions.
//
// Use this to enforce that security-sensitive packages use safe wrappers
// instead of raw stdlib functions.
func AssertNoRiskyCalls(t *testing.T, riskyCalls []RiskyCall) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}

	fset := token.NewFileSet()

	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("reading directory: %v", err)
	}

	// Build lookup map
	riskyMap := make(map[string]map[string]string) // pkg -> func -> reason
	for _, rc := range riskyCalls {
		if riskyMap[rc.Package] == nil {
			riskyMap[rc.Package] = make(map[string]string)
		}
		for _, fn := range rc.Functions {
			riskyMap[rc.Package][fn] = rc.Reason
		}
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
		file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), err)
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

			if funcs, exists := riskyMap[ident.Name]; exists {
				if reason, isRisky := funcs[sel.Sel.Name]; isRisky {
					pos := fset.Position(call.Pos())
					t.Errorf("SECURITY: %s:%d uses %s.%s\n%s",
						entry.Name(), pos.Line, ident.Name, sel.Sel.Name, reason)
				}
			}

			return true
		})
	}
}

// AssertRequiresImport fails if a package uses a given import but not
// a required companion import.
//
// Use this to ensure packages that use raw exec also import execsafe,
// or similar security wrapper requirements.
func AssertRequiresImport(t *testing.T, triggerImport, requiredImport, reason string) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}

	fset := token.NewFileSet()

	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("reading directory: %v", err)
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
		file, err := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), err)
		}

		var hasTrigger, hasRequired bool
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if importPath == triggerImport {
				hasTrigger = true
			}
			if strings.HasSuffix(importPath, requiredImport) {
				hasRequired = true
			}
		}

		if hasTrigger && !hasRequired {
			t.Errorf("SECURITY: %s imports %s but not %s\n%s",
				entry.Name(), triggerImport, requiredImport, reason)
		}
	}
}

// RepoRoot finds the repository root by looking for go.mod.
// Returns empty string if not found.
func RepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
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

// RepoWideOptions configures repo-wide import scanning.
type RepoWideOptions struct {
	// AllowedPackages lists packages exempt from the check (relative to repo root).
	AllowedPackages []string

	// IncludeTests also scans _test.go files (default: false).
	IncludeTests bool

	// WarnOnly logs violations but doesn't fail the test (default: false).
	WarnOnly bool

	// ExactMatch requires exact import path match (default: false - uses Contains).
	ExactMatch bool

	// OnlyPackages limits scanning to these packages (for focused audits).
	// If empty, scans entire repo.
	OnlyPackages []string
}

// AssertNoImportRepoWide scans the entire repository for a forbidden import.
//
// Use this for repo-wide security boundaries like "only safeyaml can import yaml.v3".
func AssertNoImportRepoWide(t *testing.T, forbiddenImport string, opts RepoWideOptions, reason string) {
	t.Helper()

	repoRoot := RepoRoot(t)
	if repoRoot == "" {
		t.Skip("could not find repo root")
	}

	allowed := make(map[string]bool)
	for _, pkg := range opts.AllowedPackages {
		allowed[pkg] = true
	}

	onlyPkgs := make(map[string]bool)
	for _, pkg := range opts.OnlyPackages {
		onlyPkgs[pkg] = true
	}

	fset := token.NewFileSet()
	var violations []string

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-Go files
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}

		// Skip test files unless opted in
		if !opts.IncludeTests && strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		// Skip vendor
		if strings.Contains(path, "/vendor/") {
			return nil
		}

		relPath, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}

		pkgPath := filepath.Dir(relPath)

		// Check OnlyPackages filter
		if len(onlyPkgs) > 0 && !onlyPkgs[pkgPath] {
			return nil
		}

		// Check allowed packages
		if allowed[pkgPath] {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil // Skip files that don't parse
		}

		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			var matches bool
			if opts.ExactMatch {
				matches = importPath == forbiddenImport
			} else {
				matches = strings.Contains(importPath, forbiddenImport)
			}
			if matches {
				violations = append(violations, relPath)
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("walking repository: %v", err)
	}

	if len(violations) > 0 {
		msg := "SECURITY VIOLATION: The following files import " + forbiddenImport + ":\n"
		for _, v := range violations {
			msg += "  - " + v + "\n"
		}
		msg += "\n" + reason

		if opts.WarnOnly {
			t.Log(msg)
		} else {
			t.Error(msg)
		}
	}
}

// PackageScanOptions configures package-specific scanning.
type PackageScanOptions struct {
	// Recursive walks subdirectories (default: false).
	Recursive bool

	// ExemptFiles lists specific files to skip (relative to repo root).
	ExemptFiles []string

	// ExemptPackages lists packages to skip entirely.
	ExemptPackages []string
}

// AssertNoImportsInPackages scans specific packages for forbidden imports.
//
// Use this for execution-boundary checks like "dispatch must not import catalog".
func AssertNoImportsInPackages(t *testing.T, packages []string, forbiddenImports []string, opts PackageScanOptions, reason string) {
	t.Helper()

	repoRoot := RepoRoot(t)
	if repoRoot == "" {
		t.Skip("could not find repo root")
	}

	exemptFiles := make(map[string]bool)
	for _, f := range opts.ExemptFiles {
		exemptFiles[f] = true
	}

	exemptPkgs := make(map[string]bool)
	for _, pkg := range opts.ExemptPackages {
		exemptPkgs[pkg] = true
	}

	fset := token.NewFileSet()

	for _, pkg := range packages {
		pkgPath := filepath.Join(repoRoot, pkg)
		if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
			continue
		}

		walkFn := func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}

			if info.IsDir() || !strings.HasSuffix(info.Name(), ".go") {
				return nil
			}
			if strings.HasSuffix(info.Name(), "_test.go") {
				return nil
			}
			if strings.Contains(info.Name(), "import_guard") {
				return nil
			}

			relPath, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}

			// Check exempt files
			if exemptFiles[relPath] {
				return nil
			}

			// Check exempt packages
			pkgDir := filepath.Dir(relPath)
			if exemptPkgs[pkgDir] {
				return nil
			}

			file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return nil
			}

			for _, imp := range file.Imports {
				importPath := strings.Trim(imp.Path.Value, `"`)
				for _, forbidden := range forbiddenImports {
					if strings.Contains(importPath, forbidden) {
						t.Errorf("SECURITY VIOLATION: %s imports %s\n%s",
							relPath, importPath, reason)
					}
				}
			}

			return nil
		}

		if opts.Recursive {
			_ = filepath.Walk(pkgPath, walkFn)
		} else {
			entries, err := os.ReadDir(pkgPath)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				info, err := entry.Info()
				if err != nil {
					continue
				}
				_ = walkFn(filepath.Join(pkgPath, entry.Name()), info, nil)
			}
		}
	}
}

// AssertNoRiskyCallsInPackages scans specific packages for risky function calls.
//
// Use this for security-sensitive operations like "component/* must use safefile".
func AssertNoRiskyCallsInPackages(t *testing.T, packages []string, riskyCalls []RiskyCall, opts PackageScanOptions) {
	t.Helper()

	repoRoot := RepoRoot(t)
	if repoRoot == "" {
		t.Skip("could not find repo root")
	}

	exemptFiles := make(map[string]bool)
	for _, f := range opts.ExemptFiles {
		exemptFiles[f] = true
	}

	exemptPkgs := make(map[string]bool)
	for _, pkg := range opts.ExemptPackages {
		exemptPkgs[pkg] = true
	}

	// Build lookup map
	riskyMap := make(map[string]map[string]string)
	for _, rc := range riskyCalls {
		if riskyMap[rc.Package] == nil {
			riskyMap[rc.Package] = make(map[string]string)
		}
		for _, fn := range rc.Functions {
			riskyMap[rc.Package][fn] = rc.Reason
		}
	}

	fset := token.NewFileSet()

	for _, pkg := range packages {
		pkgPath := filepath.Join(repoRoot, pkg)
		if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
			continue
		}

		walkFn := func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}

			if info.IsDir() || !strings.HasSuffix(info.Name(), ".go") {
				return nil
			}
			if strings.HasSuffix(info.Name(), "_test.go") {
				return nil
			}
			if strings.Contains(info.Name(), "import_guard") {
				return nil
			}

			relPath, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}

			// Check exempt files
			if exemptFiles[relPath] {
				return nil
			}

			// Check exempt packages
			pkgDir := filepath.Dir(relPath)
			if exemptPkgs[pkgDir] {
				return nil
			}

			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil
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

				if funcs, exists := riskyMap[ident.Name]; exists {
					if reason, isRisky := funcs[sel.Sel.Name]; isRisky {
						pos := fset.Position(call.Pos())
						t.Errorf("SECURITY: %s:%d uses %s.%s\n%s",
							relPath, pos.Line, ident.Name, sel.Sel.Name, reason)
					}
				}

				return true
			})

			return nil
		}

		if opts.Recursive {
			_ = filepath.Walk(pkgPath, walkFn)
		} else {
			entries, err := os.ReadDir(pkgPath)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				info, err := entry.Info()
				if err != nil {
					continue
				}
				_ = walkFn(filepath.Join(pkgPath, entry.Name()), info, nil)
			}
		}
	}
}
