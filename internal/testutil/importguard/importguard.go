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
	Package    string   // Package identifier in code (e.g., "os")
	ImportPath string   // Optional full import path to match (e.g., "github.com/locktivity/epack/pack")
	Functions  []string // Function names to flag (e.g., "Create", "WriteFile")
	Reason     string   // Why this is risky
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

	riskyMap, riskyImportMap := buildRiskyMaps(riskyCalls)

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

		inspectRiskyCalls(file, fset, riskyMap, riskyImportMap, func(line int, pkgName, fn, reason string) {
			t.Errorf("SECURITY: %s:%d uses %s.%s\n%s", entry.Name(), line, pkgName, fn, reason)
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

	allowed := makeSet(opts.AllowedPackages)
	onlyPkgs := makeSet(opts.OnlyPackages)

	fset := token.NewFileSet()
	var violations []string

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Files/directories can disappear during traversal when tests create and
			// clean up temp paths under the repo. Treat ENOENT as a benign race.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		if strings.Contains(path, "/vendor/") || !shouldScanFile(info, opts.IncludeTests, false) {
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

		matched, err := fileImportsMatch(fset, path, forbiddenImport, opts.ExactMatch)
		if err == nil && matched {
			violations = append(violations, relPath)
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

	exemptFiles := makeSet(opts.ExemptFiles)
	exemptPkgs := makeSet(opts.ExemptPackages)

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

			if !shouldScanFile(info, false, true) {
				return nil
			}

			relPath, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}

			if isExemptPath(relPath, exemptFiles, exemptPkgs) {
				return nil
			}

			importPaths, err := parseImportPaths(fset, path)
			if err != nil {
				return nil
			}
			for _, importPath := range importPaths {
				if containsAny(importPath, forbiddenImports) {
					t.Errorf("SECURITY VIOLATION: %s imports %s\n%s", relPath, importPath, reason)
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

	exemptFiles := makeSet(opts.ExemptFiles)
	exemptPkgs := makeSet(opts.ExemptPackages)
	riskyMap, riskyImportMap := buildRiskyMaps(riskyCalls)

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

			if !shouldScanFile(info, false, true) {
				return nil
			}

			relPath, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}

			if isExemptPath(relPath, exemptFiles, exemptPkgs) {
				return nil
			}

			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil
			}

			inspectRiskyCalls(file, fset, riskyMap, riskyImportMap, func(line int, pkgName, fn, reason string) {
				t.Errorf("SECURITY: %s:%d uses %s.%s\n%s", relPath, line, pkgName, fn, reason)
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

func makeSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func buildRiskyMaps(riskyCalls []RiskyCall) (map[string]map[string]string, map[string]map[string]string) {
	riskyMap := make(map[string]map[string]string)
	riskyImportMap := make(map[string]map[string]string)
	for _, rc := range riskyCalls {
		if rc.Package != "" && riskyMap[rc.Package] == nil {
			riskyMap[rc.Package] = make(map[string]string)
		}
		for _, fn := range rc.Functions {
			if rc.Package != "" {
				riskyMap[rc.Package][fn] = rc.Reason
			}
			if rc.ImportPath != "" {
				if riskyImportMap[rc.ImportPath] == nil {
					riskyImportMap[rc.ImportPath] = make(map[string]string)
				}
				riskyImportMap[rc.ImportPath][fn] = rc.Reason
			}
		}
	}
	return riskyMap, riskyImportMap
}

func shouldScanFile(info os.FileInfo, includeTests, skipImportGuard bool) bool {
	if info.IsDir() || !strings.HasSuffix(info.Name(), ".go") {
		return false
	}
	if !includeTests && strings.HasSuffix(info.Name(), "_test.go") {
		return false
	}
	if skipImportGuard && strings.Contains(info.Name(), "import_guard") {
		return false
	}
	return true
}

func isExemptPath(relPath string, exemptFiles, exemptPkgs map[string]bool) bool {
	if exemptFiles[relPath] {
		return true
	}
	return exemptPkgs[filepath.Dir(relPath)]
}

func parseImportPaths(fset *token.FileSet, path string) ([]string, error) {
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	importPaths := make([]string, 0, len(file.Imports))
	for _, imp := range file.Imports {
		importPaths = append(importPaths, strings.Trim(imp.Path.Value, `"`))
	}
	return importPaths, nil
}

func fileImportsMatch(fset *token.FileSet, path, forbiddenImport string, exact bool) (bool, error) {
	importPaths, err := parseImportPaths(fset, path)
	if err != nil {
		return false, err
	}
	for _, importPath := range importPaths {
		if exact && importPath == forbiddenImport {
			return true, nil
		}
		if !exact && strings.Contains(importPath, forbiddenImport) {
			return true, nil
		}
	}
	return false, nil
}

func containsAny(importPath string, forbiddenImports []string) bool {
	for _, forbidden := range forbiddenImports {
		if strings.Contains(importPath, forbidden) {
			return true
		}
	}
	return false
}

func inspectRiskyCalls(file *ast.File, fset *token.FileSet, riskyMap map[string]map[string]string, riskyImportMap map[string]map[string]string, report func(line int, pkgName, fn, reason string)) {
	importAliases := buildImportAliasMap(file)

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

		pkgName := ident.Name
		fnName := sel.Sel.Name

		if funcs, exists := riskyMap[pkgName]; exists {
			if reason, isRisky := funcs[fnName]; isRisky {
				report(fset.Position(call.Pos()).Line, pkgName, fnName, reason)
				return true
			}
		}

		importPath, imported := importAliases[pkgName]
		if imported {
			if funcs, exists := riskyImportMap[importPath]; exists {
				if reason, isRisky := funcs[fnName]; isRisky {
					report(fset.Position(call.Pos()).Line, pkgName, fnName, reason)
				}
			}
		}
		return true
	})
}

func buildImportAliasMap(file *ast.File) map[string]string {
	aliases := make(map[string]string, len(file.Imports))

	for _, imp := range file.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		if imp.Name != nil {
			name := imp.Name.Name
			if name == "_" || name == "." {
				continue
			}
			aliases[name] = importPath
			continue
		}

		parts := strings.Split(importPath, "/")
		if len(parts) == 0 {
			continue
		}
		aliases[parts[len(parts)-1]] = importPath
	}

	return aliases
}

// SelectorCallRule describes forbidden selector method/function names.
type SelectorCallRule struct {
	// SelectorNames are method/function names to ban (e.g., ReadFileUntrusted).
	SelectorNames []string
	// RequiredImports optionally gates matching to files importing one of these paths.
	RequiredImports []string
	// Reason explains why this selector is forbidden.
	Reason string
}

// AssertNoSelectorCallsInPackages scans selected packages for forbidden selector names.
//
// This catches calls like p.ReadFileUntrusted(...) where the receiver is a variable,
// which package-identifier based checks cannot reliably detect.
func AssertNoSelectorCallsInPackages(t *testing.T, packages []string, rules []SelectorCallRule, opts PackageScanOptions) {
	t.Helper()

	repoRoot := RepoRoot(t)
	if repoRoot == "" {
		t.Skip("could not find repo root")
	}

	exemptFiles := makeSet(opts.ExemptFiles)
	exemptPkgs := makeSet(opts.ExemptPackages)
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

			if !shouldScanFile(info, false, true) {
				return nil
			}

			relPath, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			if isExemptPath(relPath, exemptFiles, exemptPkgs) {
				return nil
			}

			file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.ParseComments)
			if err != nil {
				return nil
			}
			importPaths := make(map[string]bool, len(file.Imports))
			for _, imp := range file.Imports {
				importPaths[strings.Trim(imp.Path.Value, `"`)] = true
			}

			file, err = parser.ParseFile(fset, path, nil, parser.ParseComments)
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

				for _, rule := range rules {
					if !selectorAllowedByImports(rule.RequiredImports, importPaths) {
						continue
					}
					if containsName(rule.SelectorNames, sel.Sel.Name) {
						t.Errorf("SECURITY: %s:%d calls %s\n%s",
							relPath, fset.Position(call.Pos()).Line, sel.Sel.Name, rule.Reason)
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

func selectorAllowedByImports(requiredImports []string, imports map[string]bool) bool {
	if len(requiredImports) == 0 {
		return true
	}
	for _, required := range requiredImports {
		if imports[required] {
			return true
		}
	}
	return false
}

func containsName(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
