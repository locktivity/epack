//go:build components

package componentcmd

import (
	"context"
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
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/platform"
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
	installComponentNoRefresh  bool
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
		"force full catalog refresh (ignore cached data)")
	cmd.Flags().BoolVar(&installComponentNoRefresh, "no-refresh", false,
		"skip catalog refresh (use cached catalog only)")
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
		"force full catalog refresh (ignore cached data)")
	cmd.Flags().BoolVar(&installComponentNoRefresh, "no-refresh", false,
		"skip catalog refresh (use cached catalog only)")
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
		"force full catalog refresh (ignore cached data)")
	cmd.Flags().BoolVar(&installComponentNoRefresh, "no-refresh", false,
		"skip catalog refresh (use cached catalog only)")
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

	parsed, err := parseInstallArgument(args[0])
	if err != nil {
		return err
	}
	if err := ensureInstallProject(); err != nil {
		return err
	}
	if err := refreshInstallCatalog(ctx, out); err != nil {
		return err
	}

	cat, err := readInstallCatalog(kind, parsed.Name)
	if err != nil {
		return err
	}

	toInstall, err := resolveInstallDependencies(out, inst, kind, cat, parsed)
	if err != nil {
		return err
	}
	components, err := lookupInstallComponents(inst, kind, cat, parsed, toInstall)
	if err != nil {
		return err
	}

	newComponents := filterNewComponents(components)
	if len(newComponents) == 0 {
		out.Print("%s %q is already installed\n\n", kind.Title(), parsed.Name)
		out.Print("To update: epack update %s\n", parsed.Name)
		return nil
	}

	if installComponentDryRun {
		return printInstallDryRun(out, kind, newComponents)
	}
	return installAndSyncComponents(ctx, out, inst, kind, newComponents)
}

type installOutput interface {
	Print(format string, args ...interface{})
}

func parseInstallArgument(arg string) (*resolve.ParsedComponent, error) {
	parsed, err := resolve.ParseComponentArg(arg)
	if err != nil {
		return nil, &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("invalid argument: %v", err),
		}
	}
	return parsed, nil
}

func ensureInstallProject() error {
	if _, err := os.Stat(installComponentConfigPath); os.IsNotExist(err) {
		return &exitError{
			Exit: exitcode.General,
			Message: fmt.Sprintf(`No epack project found (missing %s)

To create a new project:     epack new my-project
To initialize this directory: epack init`, installComponentConfigPath),
		}
	}
	return nil
}

func refreshInstallCatalog(ctx context.Context, out installOutput) error {
	if installComponentNoRefresh {
		return nil
	}

	opts := catalog.FetchOptions{}
	if !installComponentRefresh {
		if meta, err := catalog.ReadMeta(); err == nil {
			opts.ETag = meta.ETag
			opts.LastModified = meta.LastModified
		}
	}

	out.Print("Checking catalog...\n")
	result, err := catalog.FetchCatalog(ctx, opts)
	if err != nil {
		return &exitError{
			Exit:    exitcode.Network,
			Message: fmt.Sprintf("fetching catalog: %v", err),
		}
	}
	if result.Status == catalog.MetaStatusNotModified {
		out.Print("  catalog is up to date\n")
	} else if result.Updated {
		out.Print("  catalog updated\n")
	}
	return nil
}

func readInstallCatalog(kind componentKind, name string) (*catalog.Catalog, error) {
	cat, _, err := catalog.ReadCatalog()
	if err == nil {
		return cat, nil
	}
	if errors.Is(err, catalog.ErrNoCatalog) {
		return nil, &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("catalog not found; run 'epack install %s --refresh %s'", kind, name),
		}
	}
	return nil, &exitError{
		Exit:    exitcode.General,
		Message: fmt.Sprintf("reading catalog: %v", err),
	}
}

func resolveInstallDependencies(out installOutput, inst componentInstaller, kind componentKind, cat *catalog.Catalog, parsed *resolve.ParsedComponent) ([]resolve.ResolvedDependency, error) {
	if !inst.supportsDeps || installComponentNoDeps {
		return []resolve.ResolvedDependency{{Name: parsed.Name, IsDirect: true}}, nil
	}

	out.Print("Resolving dependencies...\n")
	toInstall, err := resolve.ResolveDependencies(cat, parsed.Name)
	if err != nil {
		return nil, mapResolveDependencyError(err, kind, parsed.Name)
	}
	if len(toInstall) > 1 {
		for _, dep := range toInstall[:len(toInstall)-1] {
			out.Print("  %s -> %s\n", parsed.Name, dep.Name)
		}
	}
	return toInstall, nil
}

func mapResolveDependencyError(err error, kind componentKind, name string) error {
	if errors.Is(err, catalog.ErrNotFound) {
		return &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("%s %q not found in catalog\n\nTry: epack tool catalog search %s", kind, name, name),
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
			Message: fmt.Sprintf("%v\n\nThe catalog may be out of date; try: epack install %s --refresh %s", err, kind, name),
		}
	}
	return &exitError{
		Exit:    exitcode.General,
		Message: fmt.Sprintf("resolving dependencies: %v", err),
	}
}

func lookupInstallComponents(inst componentInstaller, kind componentKind, cat *catalog.Catalog, parsed *resolve.ParsedComponent, deps []resolve.ResolvedDependency) ([]componentToInstall, error) {
	components := make([]componentToInstall, 0, len(deps))
	for _, dep := range deps {
		exists, err := inst.hasComponent(installComponentConfigPath, dep.Name)
		if err != nil {
			return nil, &exitError{
				Exit:    exitcode.General,
				Message: fmt.Sprintf("checking config: %v", err),
			}
		}

		constraint := "latest"
		if dep.IsDirect {
			constraint = parsed.Constraint
		}

		result, err := catalog.LookupComponentInCatalog(cat, dep.Name, kind.CatalogKind(), constraint)
		if err != nil {
			return nil, &exitError{
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
	return components, nil
}

func filterNewComponents(components []componentToInstall) []componentToInstall {
	var newComponents []componentToInstall
	for _, c := range components {
		if !c.AlreadyIn {
			newComponents = append(newComponents, c)
		}
	}
	return newComponents
}

func printInstallDryRun(out installOutput, kind componentKind, newComponents []componentToInstall) error {
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

func installAndSyncComponents(ctx context.Context, out installOutput, inst componentInstaller, kind componentKind, newComponents []componentToInstall) error {
	if len(newComponents) == 1 {
		out.Print("Installing %s %s...\n", kind, newComponents[0].Name)
	} else {
		out.Print("\nInstalling %d %s:\n", len(newComponents), kind.Plural())
	}
	if err := addInstallComponents(inst, out, newComponents); err != nil {
		return err
	}
	filteredCfg, workDir, err := prepareInstallSync(newComponents, out)
	if err != nil {
		return err
	}
	lockResults, err := lockInstallComponents(ctx, workDir, filteredCfg)
	if err != nil {
		return err
	}
	for _, r := range lockResults {
		out.Print("  locked %s@%s\n", r.Name, r.Version)
	}
	syncResults, err := syncInstallComponents(ctx, workDir, filteredCfg)
	if err != nil {
		return err
	}
	for _, r := range syncResults {
		if r.Installed {
			out.Print("  installed %s@%s\n", r.Name, r.Version)
		}
	}
	printInstallSummary(out, kind, newComponents, workDir)
	return nil
}

func addInstallComponents(inst componentInstaller, out installOutput, newComponents []componentToInstall) error {
	for _, c := range newComponents {
		if len(newComponents) > 1 {
			if c.IsDirect {
				out.Print("  + %s\n", c.Name)
			} else {
				out.Print("  + %s (dependency of %s)\n", c.Name, c.DependedBy)
			}
		}
		err := inst.addComponent(installComponentConfigPath, c.Name, c.Source)
		if err == nil || errors.Is(err, config.ErrAlreadyExists) {
			continue
		}
		return &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("adding %q to config: %v", c.Name, err),
		}
	}
	return nil
}

func prepareInstallSync(newComponents []componentToInstall, out installOutput) (*config.JobConfig, string, error) {
	out.Print("Locking and syncing...\n")

	cfg, err := loadConfig(installComponentConfigPath)
	if err != nil {
		return nil, "", &exitError{
			Exit:    exitcode.General,
			Message: fmt.Sprintf("loading config: %v", err),
		}
	}
	workDir, err := resolveWorkDir()
	if err != nil {
		return nil, "", handleComponentError(err)
	}
	names := make([]string, 0, len(newComponents))
	for _, c := range newComponents {
		names = append(names, c.Name)
	}
	filteredCfg, err := filterConfigComponents(cfg, names)
	if err != nil {
		return nil, "", handleComponentError(err)
	}
	return filteredCfg, workDir, nil
}

func lockInstallComponents(ctx context.Context, workDir string, cfg *config.JobConfig) ([]sync.LockResult, error) {
	locker := sync.NewLocker(workDir)
	lockResults, err := locker.Lock(ctx, cfg, sync.LockOpts{
		Platforms: []string{platform.Key(runtime.GOOS, runtime.GOARCH)},
	})
	if err != nil {
		return nil, handleComponentError(err)
	}
	return lockResults, nil
}

func syncInstallComponents(ctx context.Context, workDir string, cfg *config.JobConfig) ([]sync.SyncResult, error) {
	syncer := sync.NewSyncer(workDir)
	syncResults, err := syncer.Sync(ctx, cfg, sync.SyncOpts{
		SkipStaleEntryCheck: true,
	})
	if err != nil {
		return nil, handleComponentError(err)
	}
	return syncResults, nil
}

func printInstallSummary(out installOutput, kind componentKind, newComponents []componentToInstall, workDir string) {
	out.Print("\nAdded to %s:\n", installComponentConfigPath)
	for _, c := range newComponents {
		out.Print("  %s.%s: %s\n", kind.Plural(), c.Name, c.Source)
	}
	if len(newComponents) == 1 {
		out.Print("\n✓ Installed %s %s\n", kind, newComponents[0].Name)
	} else {
		out.Print("\n✓ Installed %d %s\n", len(newComponents), kind.Plural())
	}
	out.Print("Remember to commit %s\n", filepath.Join(workDir, "epack.lock.yaml"))
}
