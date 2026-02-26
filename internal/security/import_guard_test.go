// Package security provides security utilities and import guards.
package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestNoUnsafeFileOps ensures security-sensitive packages use safe file operations.
//
// SECURITY BOUNDARY: Packages that handle untrusted data must use:
//   - safefile.* functions (O_NOFOLLOW, symlink prevention, atomic writes)
//   - execsafe.* functions (TOCTOU-safe execution)
//
// Direct use of these stdlib functions bypasses symlink and TOCTOU protections:
//   - os.Create, os.WriteFile, os.OpenFile, os.MkdirAll, os.Rename (vulnerable to symlink attacks)
//   - os.Open without O_NOFOLLOW (follows symlinks)
//
// This test flags violations but allows exceptions in test files.
func TestNoUnsafeFileOps(t *testing.T) {
	importguard.AssertNoRiskyCallsInPackages(t,
		[]string{
			"internal/dispatch",
			"internal/collector",
			"internal/remote",
			"internal/pull",
			"internal/push",
			"internal/component/sync",
			"pack/extract",
		},
		[]importguard.RiskyCall{
			{
				Package:   "os",
				Functions: []string{"Create", "WriteFile", "OpenFile", "MkdirAll", "Rename"},
				Reason:    "This function doesn't use O_NOFOLLOW and is vulnerable to symlink attacks.\nUse safefile functions instead.",
			},
		},
		importguard.PackageScanOptions{
			ExemptFiles: []string{},
		},
	)
}

// TestNoUnsafeFileOpsInUserConfigSyncer ensures utility install/sync code paths
// in userconfig do not bypass safe file primitives.
func TestNoUnsafeFileOpsInUserConfigSyncer(t *testing.T) {
	importguard.AssertNoRiskyCallsInPackages(t,
		[]string{
			"internal/userconfig",
		},
		[]importguard.RiskyCall{
			{
				Package:   "os",
				Functions: []string{"Create", "WriteFile", "OpenFile", "MkdirAll", "Rename"},
				Reason:    "Utility install/sync paths must use safefile or safefile/tx wrappers.",
			},
		},
		importguard.PackageScanOptions{
			ExemptFiles: []string{},
		},
	)
}

// TestNoUntrustedPackReadsInSensitivePackages prevents accidental use of
// untrusted pack reads in execution-sensitive code.
func TestNoUntrustedPackReadsInSensitivePackages(t *testing.T) {
	importguard.AssertNoSelectorCallsInPackages(t,
		[]string{
			"internal/dispatch",
			"internal/collector",
			"internal/remote",
			"internal/pull",
			"internal/push",
		},
		[]importguard.SelectorCallRule{
			{
				SelectorNames: []string{
					"ReadFileUntrusted",
					"ReadFileUntrustedWithBudget",
					"OpenFileUntrusted",
					"OpenFileUntrustedWithBudget",
				},
				RequiredImports: []string{"github.com/locktivity/epack/pack"},
				Reason:          "Untrusted pack reads are not allowed in security-sensitive execution paths.\nUse verified pack APIs and explicit integrity checks instead.",
			},
		},
		importguard.PackageScanOptions{
			Recursive: true,
		},
	)
}

// TestNoRawExecImportInSensitivePackages ensures critical execution packages
// do not directly import os/exec.
func TestNoRawExecImportInSensitivePackages(t *testing.T) {
	importguard.AssertNoImportsInPackages(t,
		[]string{
			"internal/dispatch",
			"internal/collector",
			"internal/remote",
			"internal/pull",
			"internal/push",
			"internal/detach",
			"internal/toolcap",
			"cmd/epack/cmd",
			"cmd/epack/remotecmd",
			"cmd/epack/toolcmd",
			"cmd/epack/collectorcmd",
			"cmd/epack/utilitycmd",
			"cmd/epack/componentcmd",
		},
		[]string{"os/exec"},
		importguard.PackageScanOptions{
			Recursive: true,
		},
		"Sensitive execution packages must use internal/procexec wrappers instead of raw os/exec imports.")
}

// TestNoRawProcexecCommandOutsideWrapper ensures callers use policy-enforcing
// procexec APIs (Run/Output/RunCapture/CommandChecked) instead of raw Command.
func TestNoRawProcexecCommandOutsideWrapper(t *testing.T) {
	importguard.AssertNoSelectorCallsInPackages(t,
		[]string{
			"internal",
			"cmd",
		},
		[]importguard.SelectorCallRule{
			{
				SelectorNames: []string{"Command"},
				RequiredImports: []string{
					"github.com/locktivity/epack/internal/procexec",
				},
				Reason: "Direct procexec.Command bypasses policy checks. Use CommandChecked/Run/Output/RunCapture instead.",
			},
		},
		importguard.PackageScanOptions{
			Recursive: true,
			ExemptPackages: []string{
				"internal/procexec",
			},
		},
	)
}

// TestNoCatalogImportInExecution ensures execution packages don't import catalog.
//
// SECURITY BOUNDARY: The catalog package is for DISCOVERY ONLY.
// Execution decisions (which binary to run, what digest to verify) must come
// from the lockfile, not the catalog. Importing catalog in execution packages
// creates a risk that untrusted catalog data influences security decisions.
func TestNoCatalogImportInExecution(t *testing.T) {
	importguard.AssertNoImportsInPackages(t,
		[]string{
			"internal/dispatch",
			"internal/collector",
			"internal/component/sync",
		},
		[]string{"internal/catalog"},
		importguard.PackageScanOptions{},
		"Execution packages must NOT import internal/catalog.\n"+
			"Catalog data is for discovery/display only.\n"+
			"Execution decisions must come from the lockfile.")
}

// TestSecurityPolicyAndAuditCallsScopedInCLI ensures top-level CLI packages keep
// securitypolicy/securityaudit calls centralized in validation/approved gates.
func TestSecurityPolicyAndAuditCallsScopedInCLI(t *testing.T) {
	repoRoot := importguard.RepoRoot(t)
	if repoRoot == "" {
		t.Skip("could not find repo root")
	}

	packages := []string{
		"cmd/epack/cmd",
		"cmd/epack/remotecmd",
		"cmd/epack/toolcmd",
		"cmd/epack/collectorcmd",
		"cmd/epack/componentcmd",
		"cmd/epack/utilitycmd",
	}

	allowedAuditFns := map[string]bool{
		"runCatalogRefresh":        true,
		"runUnifiedCatalogRefresh": true,
	}

	fset := token.NewFileSet()
	for _, pkg := range packages {
		pkgPath := filepath.Join(repoRoot, pkg)
		_ = filepath.Walk(pkgPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			file, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				t.Fatalf("parsing %s: %v", path, parseErr)
			}

			relPath, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				relPath = path
			}

			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				fnName := fn.Name.Name
				isValidateFlagsFn := strings.HasPrefix(fnName, "validate") && strings.HasSuffix(fnName, "Flags")

				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkgIdent, ok := sel.X.(*ast.Ident)
					if !ok {
						return true
					}

					if pkgIdent.Name == "securitypolicy" && sel.Sel.Name == "EnforceStrictProduction" && !isValidateFlagsFn {
						t.Errorf("SECURITY: %s uses securitypolicy.EnforceStrictProduction outside validate*Flags (%s)", relPath, fnName)
					}
					if pkgIdent.Name == "securityaudit" && sel.Sel.Name == "Emit" &&
						!isValidateFlagsFn && !allowedAuditFns[fnName] {
						t.Errorf("SECURITY: %s uses securityaudit.Emit outside approved gate (%s)", relPath, fnName)
					}
					return true
				})
			}

			return nil
		})
	}
}
