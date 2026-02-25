//go:build components

package componentcmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/locktivity/epack/internal/catalog"
	"github.com/locktivity/epack/internal/catalog/resolve"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/spf13/cobra"
)

// componentKind distinguishes tools, collectors, and remotes for the unified installer.
type componentKind int

const (
	kindTool componentKind = iota
	kindCollector
	kindRemote
)

func (k componentKind) String() string {
	switch k {
	case kindTool:
		return "tool"
	case kindCollector:
		return "collector"
	case kindRemote:
		return "remote"
	default:
		return "component"
	}
}

func (k componentKind) Plural() string {
	return k.String() + "s"
}

// Title returns the kind with first letter capitalized.
func (k componentKind) Title() string {
	s := k.String()
	return strings.ToUpper(s[:1]) + s[1:]
}

// CatalogKind returns the catalog.ComponentKind for lookup operations.
func (k componentKind) CatalogKind() catalog.ComponentKind {
	switch k {
	case kindTool:
		return catalog.KindTool
	case kindCollector:
		return catalog.KindCollector
	case kindRemote:
		return catalog.KindRemote
	default:
		// This should never happen - if we add new kinds, update this switch
		panic("unknown component kind")
	}
}

// componentToInstall holds info about a component to install.
type componentToInstall struct {
	Name       string
	Source     string
	IsDirect   bool
	DependedBy string
	AlreadyIn  bool
}

// componentInstaller encapsulates type-specific operations for installing components.
type componentInstaller struct {
	kind         componentKind
	hasComponent func(configPath, name string) (bool, error)
	addComponent func(configPath, name, source string) error
	supportsDeps bool
}

var (
	installComponentConfigPath string
	installComponentRefresh    bool
	installComponentNoDeps     bool
	installComponentDryRun     bool
)

func newInstallToolCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tool <name>[@version]",
		Short: "Install a tool from the catalog",
		Long: `Install a tool by looking it up in the catalog and adding it to epack.yaml.

The tool is looked up in the catalog to discover its source repository,
then added to your epack.yaml configuration, locked, and synced.

Dependencies are automatically resolved and installed in the correct order.

Version constraints:
  ask          Use latest version
  ask@latest   Same as above
  ask@^1.0     Caret: >=1.0.0 <2.0.0
  ask@~1.2     Tilde: >=1.2.0 <1.3.0
  ask@v1.2.3   Exact version

Examples:
  epack install tool ask           Install latest version with dependencies
  epack install tool ask@^1.0      Install with caret constraint
  epack install tool ask --no-deps Install without dependencies
  epack install tool ask --dry-run Preview what would be installed`,
		Args: cobra.ExactArgs(1),
		RunE: runInstallTool,
	}

	cmd.Flags().StringVarP(&installComponentConfigPath, "config", "c", "epack.yaml",
		"path to epack config file")
	cmd.Flags().BoolVar(&installComponentRefresh, "refresh", false,
		"refresh catalog before lookup")
	cmd.Flags().BoolVar(&installComponentNoDeps, "no-deps", false,
		"skip installing dependencies")
	cmd.Flags().BoolVar(&installComponentDryRun, "dry-run", false,
		"show what would be installed without making changes")

	return cmd
}

func newInstallCollectorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collector <name>[@version]",
		Short: "Install a collector from the catalog",
		Long: `Install a collector by looking it up in the catalog and adding it to epack.yaml.

The collector is looked up in the catalog to discover its source repository,
then added to your epack.yaml configuration, locked, and synced.

Version constraints:
  github          Use latest version
  github@latest   Same as above
  github@^1.0     Caret: >=1.0.0 <2.0.0
  github@~1.2     Tilde: >=1.2.0 <1.3.0
  github@v1.2.3   Exact version

Examples:
  epack install collector github           Install latest version
  epack install collector github@^1.0      Install with caret constraint
  epack install collector github --dry-run Preview what would be installed`,
		Args: cobra.ExactArgs(1),
		RunE: runInstallCollector,
	}

	cmd.Flags().StringVarP(&installComponentConfigPath, "config", "c", "epack.yaml",
		"path to epack config file")
	cmd.Flags().BoolVar(&installComponentRefresh, "refresh", false,
		"refresh catalog before lookup")
	cmd.Flags().BoolVar(&installComponentDryRun, "dry-run", false,
		"show what would be installed without making changes")

	return cmd
}

func newInstallRemoteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote <name>[@version]",
		Short: "Install a remote from the catalog",
		Long: `Install a remote by looking it up in the catalog and adding it to epack.yaml.

The remote is looked up in the catalog to discover its source repository,
then added to your epack.yaml configuration, locked, and synced.

Version constraints:
  locktivity          Use latest version
  locktivity@latest   Same as above
  locktivity@^1.0     Caret: >=1.0.0 <2.0.0
  locktivity@~1.2     Tilde: >=1.2.0 <1.3.0
  locktivity@v1.2.3   Exact version

Examples:
  epack install remote locktivity           Install latest version
  epack install remote locktivity@^1.0      Install with caret constraint
  epack install remote locktivity --dry-run Preview what would be installed`,
		Args: cobra.ExactArgs(1),
		RunE: runInstallRemote,
	}

	cmd.Flags().StringVarP(&installComponentConfigPath, "config", "c", "epack.yaml",
		"path to epack config file")
	cmd.Flags().BoolVar(&installComponentRefresh, "refresh", false,
		"refresh catalog before lookup")
	cmd.Flags().BoolVar(&installComponentDryRun, "dry-run", false,
		"show what would be installed without making changes")

	return cmd
}

func runInstallTool(cmd *cobra.Command, args []string) error {
	return runInstallComponent(cmd, args, toolInstaller)
}

func runInstallCollector(cmd *cobra.Command, args []string) error {
	return runInstallComponent(cmd, args, collectorInstaller)
}

func runInstallRemote(cmd *cobra.Command, args []string) error {
	return runInstallComponent(cmd, args, remoteInstaller)
}

// Installer instances for tools, collectors, and remotes
var (
	toolInstaller = componentInstaller{
		kind: kindTool,
		hasComponent: func(configPath, name string) (bool, error) {
			return config.HasTool(configPath, name)
		},
		addComponent: func(configPath, name, source string) error {
			return config.AddTool(configPath, name, config.ToolConfig{Source: source})
		},
		supportsDeps: true,
	}

	collectorInstaller = componentInstaller{
		kind: kindCollector,
		hasComponent: func(configPath, name string) (bool, error) {
			return config.HasCollector(configPath, name)
		},
		addComponent: func(configPath, name, source string) error {
			return config.AddCollector(configPath, name, config.CollectorConfig{Source: source})
		},
		supportsDeps: false,
	}

	remoteInstaller = componentInstaller{
		kind: kindRemote,
		hasComponent: func(configPath, name string) (bool, error) {
			return config.HasRemote(configPath, name)
		},
		addComponent: func(configPath, name, source string) error {
			return config.AddRemote(configPath, name, config.RemoteConfig{Source: source})
		},
		supportsDeps: false,
	}
)

// runInstallComponent is the unified implementation for installing tools and collectors.
func runInstallComponent(cmd *cobra.Command, args []string, inst componentInstaller) error {
	ctx := cmd.Context()
	out := getOutput(cmd)
	kind := inst.kind

	// Parse the argument
	parsed, err := resolve.ParseComponentArg(args[0])
	if err != nil {
		return &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("invalid argument: %v", err),
		}
	}

	// Check if we're in an epack project
	if _, err := os.Stat(installComponentConfigPath); os.IsNotExist(err) {
		return &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf(`No epack project found (missing %s)

To create a new project:     epack new my-project
To initialize this directory: epack init`, installComponentConfigPath),
		}
	}

	// Refresh catalog if requested or missing
	if installComponentRefresh || !catalog.Exists() {
		out.Print("Refreshing catalog...\n")
		_, err := catalog.FetchCatalog(ctx, catalog.FetchOptions{})
		if err != nil {
			return &exitError{
				Exit:    exitcode.Network,
				Message: fmt.Sprintf("fetching catalog: %v", err),
			}
		}
	}

	// Load the cached catalog
	cat, _, err := catalog.ReadCatalog()
	if err != nil {
		if errors.Is(err, catalog.ErrNoCatalog) {
			return &exitError{
				Exit:    exitcode.General,
				Message: fmt.Sprintf("catalog not found; run 'epack install %s --refresh %s'", kind, parsed.Name),
			}
		}
		return &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("reading catalog: %v", err),
		}
	}

	// Resolve what to install
	var toInstall []resolve.ResolvedDependency
	if inst.supportsDeps && !installComponentNoDeps {
		out.Print("Resolving dependencies...\n")
		toInstall, err = resolve.ResolveDependencies(cat, parsed.Name)
		if err != nil {
			if errors.Is(err, catalog.ErrNotFound) {
				return &exitError{
					Exit:    exitcode.General,
					Message: fmt.Sprintf("%s %q not found in catalog\n\nTry: epack tool catalog search %s", kind, parsed.Name, parsed.Name),
				}
			}
			if errors.Is(err, resolve.ErrCircularDependency) {
				return &exitError{
					Exit:    exitcode.General,
					Message: fmt.Sprintf("circular dependency: %v", err),
				}
			}
			if errors.Is(err, resolve.ErrDependencyNotFound) {
				return &exitError{
					Exit:    exitcode.General,
					Message: fmt.Sprintf("%v\n\nThe catalog may be out of date; try: epack install %s --refresh %s", err, kind, parsed.Name),
				}
			}
			return &exitError{
				Exit:    exitcode.General,
				Message: fmt.Sprintf("resolving dependencies: %v", err),
			}
		}

		// Show dependency chain
		if len(toInstall) > 1 {
			for _, dep := range toInstall[:len(toInstall)-1] {
				out.Print("  %s -> %s\n", parsed.Name, dep.Name)
			}
		}
	} else {
		// No dependency resolution - just install the requested component
		toInstall = []resolve.ResolvedDependency{{
			Name:     parsed.Name,
			IsDirect: true,
		}}
	}

	// Look up each component and determine what needs to be installed
	var components []componentToInstall
	for _, dep := range toInstall {
		// Check if already in config
		exists, err := inst.hasComponent(installComponentConfigPath, dep.Name)
		if err != nil {
			return &exitError{
				Exit:    exitcode.General,
				Message: fmt.Sprintf("checking config: %v", err),
			}
		}

		// Determine constraint: use specified for direct, latest for deps
		constraint := "latest"
		if dep.IsDirect {
			constraint = parsed.Constraint
		}

		// Look up in catalog
		result, err := catalog.LookupComponentInCatalog(cat, dep.Name, kind.CatalogKind(), constraint)
		if err != nil {
			return &exitError{
				Exit:    exitcode.General,
				Message: fmt.Sprintf("looking up %q: %v", dep.Name, err),
			}
		}

		components = append(components, componentToInstall{
			Name:       dep.Name,
			Source:     result.Source,
			IsDirect:   dep.IsDirect,
			DependedBy: dep.DependedBy,
			AlreadyIn:  exists,
		})
	}

	// Filter to new components only
	var newComponents []componentToInstall
	for _, c := range components {
		if !c.AlreadyIn {
			newComponents = append(newComponents, c)
		}
	}

	// If everything is already installed, report it
	if len(newComponents) == 0 {
		out.Print("%s %q is already installed\n\n", kind.Title(), parsed.Name)
		out.Print("To update: epack update %s\n", parsed.Name)
		return nil
	}

	// Dry run: just show what would happen
	if installComponentDryRun {
		out.Print("\nWould install:\n")
		for _, c := range newComponents {
			if c.IsDirect {
				out.Print("  + %s\n", c.Name)
			} else {
				out.Print("  + %s (dependency of %s)\n", c.Name, c.DependedBy)
			}
		}
		out.Print("\nWould add to %s:\n", installComponentConfigPath)
		for _, c := range newComponents {
			out.Print("  %s.%s: %s\n", kind.Plural(), c.Name, c.Source)
		}
		out.Print("\nRun without --dry-run to install.\n")
		return nil
	}

	// Add components to config
	if len(newComponents) == 1 {
		out.Print("Installing %s %s...\n", kind, newComponents[0].Name)
	} else {
		out.Print("\nInstalling %d %s:\n", len(newComponents), kind.Plural())
	}
	for _, c := range newComponents {
		if len(newComponents) > 1 {
			if c.IsDirect {
				out.Print("  + %s\n", c.Name)
			} else {
				out.Print("  + %s (dependency of %s)\n", c.Name, c.DependedBy)
			}
		}

		err := inst.addComponent(installComponentConfigPath, c.Name, c.Source)
		if err != nil {
			if errors.Is(err, config.ErrAlreadyExists) {
				// This can happen in a race; skip it
				continue
			}
			return &exitError{
				Exit:    exitcode.General,
				Message: fmt.Sprintf("adding %q to config: %v", c.Name, err),
			}
		}
	}

	// Lock and sync
	out.Print("Locking and syncing...\n")

	cfg, err := loadConfig(installComponentConfigPath)
	if err != nil {
		return &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("loading config: %v", err),
		}
	}

	workDir, err := resolveWorkDir()
	if err != nil {
		return handleComponentError(err)
	}

	// Filter to just the new components
	var newNames []string
	for _, c := range newComponents {
		newNames = append(newNames, c.Name)
	}

	filteredCfg, err := filterConfigComponents(cfg, newNames)
	if err != nil {
		return handleComponentError(err)
	}

	// Lock
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	locker := sync.NewLocker(workDir)
	lockResults, err := locker.Lock(ctx, filteredCfg, sync.LockOpts{
		Platforms: []string{platform},
	})
	if err != nil {
		return handleComponentError(err)
	}

	for _, r := range lockResults {
		out.Print("  locked %s@%s\n", r.Name, r.Version)
	}

	// Sync
	syncer := sync.NewSyncer(workDir)
	syncResults, err := syncer.Sync(ctx, filteredCfg, sync.SyncOpts{})
	if err != nil {
		return handleComponentError(err)
	}

	for _, r := range syncResults {
		if r.Installed {
			out.Print("  installed %s@%s\n", r.Name, r.Version)
		}
	}

	// Summary
	out.Print("\nAdded to %s:\n", installComponentConfigPath)
	for _, c := range newComponents {
		out.Print("  %s.%s: %s\n", kind.Plural(), c.Name, c.Source)
	}

	if len(newComponents) == 1 {
		out.Print("\n✓ Installed %s %s\n", kind, newComponents[0].Name)
	} else {
		out.Print("\n✓ Installed %d %s\n", len(newComponents), kind.Plural())
	}

	// Remind about lockfile
	lockfilePath := filepath.Join(workDir, "epack.lock.yaml")
	out.Print("Remember to commit %s\n", lockfilePath)

	return nil
}
