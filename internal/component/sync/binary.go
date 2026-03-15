package sync

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/platform"
)

// InstallPath returns deterministic install location for source-based components.
// All path components are validated to prevent path traversal attacks.
func InstallPath(baseDir string, kind componenttypes.ComponentKind, name, version, binaryName string) (string, error) {
	if err := validateInstallNames(kind, name, binaryName); err != nil {
		return "", err
	}
	if err := validateInstallVersion(version); err != nil {
		return "", err
	}
	return filepath.Join(baseDir, kind.Plural(), name, version, runtime.GOOS+"-"+runtime.GOARCH, binaryName), nil
}

func validateInstallNames(kind componenttypes.ComponentKind, name, binaryName string) error {
	validateName, err := nameValidator(kind)
	if err != nil {
		return err
	}
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid %s name: %w", kind, err)
	}
	if err := validateName(binaryName); err != nil {
		return fmt.Errorf("invalid binary name: %w", err)
	}
	return nil
}

func nameValidator(kind componenttypes.ComponentKind) (func(string) error, error) {
	switch kind {
	case componenttypes.KindCollector:
		return config.ValidateCollectorName, nil
	case componenttypes.KindTool:
		return config.ValidateToolName, nil
	case componenttypes.KindRemote:
		return config.ValidateRemoteName, nil
	default:
		return nil, fmt.Errorf("unknown component kind: %s", kind)
	}
}

func validateInstallVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if err := config.ValidateVersion(version); err != nil {
		return fmt.Errorf("invalid version: %w", err)
	}
	return nil
}

// ResolveBinaryPath resolves a collector binary path from config + lockfile.
// For source-based collectors, it returns deterministic install path.
// For external collectors, it returns the configured absolute binary path.
func ResolveBinaryPath(baseDir, collectorName string, cfg config.CollectorConfig, lf *lockfile.LockFile) (string, error) {
	if cfg.Source == "" && cfg.Binary == "" {
		return "", fmt.Errorf("collector %q has no source or binary", collectorName)
	}

	if cfg.Binary != "" {
		if !filepath.IsAbs(cfg.Binary) {
			return "", fmt.Errorf("collector %q binary must be absolute path", collectorName)
		}
		return cfg.Binary, nil
	}

	locked, ok := lf.GetCollector(collectorName)
	if !ok {
		return "", fmt.Errorf("collector %q not found in lockfile", collectorName)
	}
	if locked.Version == "" {
		return "", fmt.Errorf("collector %q lock entry missing version", collectorName)
	}
	if _, ok := locked.Platforms[platform.Key(runtime.GOOS, runtime.GOARCH)]; !ok {
		return "", fmt.Errorf("collector %q lock entry missing platform %s", collectorName, platform.Key(runtime.GOOS, runtime.GOARCH))
	}

	// Keep naming deterministic and simple in v1.
	binaryName := collectorName
	return InstallPath(baseDir, componenttypes.KindCollector, collectorName, locked.Version, binaryName)
}

// ResolveToolBinaryPath resolves a tool binary path from config + lockfile.
// For source-based tools, it returns deterministic install path.
// For external tools, it returns the configured absolute binary path.
func ResolveToolBinaryPath(baseDir, toolName string, cfg config.ToolConfig, lf *lockfile.LockFile) (string, error) {
	if cfg.Source == "" && cfg.Binary == "" {
		return "", fmt.Errorf("tool %q has no source or binary", toolName)
	}

	if cfg.Binary != "" {
		if !filepath.IsAbs(cfg.Binary) {
			return "", fmt.Errorf("tool %q binary must be absolute path", toolName)
		}
		return cfg.Binary, nil
	}

	locked, ok := lf.GetTool(toolName)
	if !ok {
		return "", fmt.Errorf("tool %q not found in lockfile", toolName)
	}
	if locked.Version == "" {
		return "", fmt.Errorf("tool %q lock entry missing version", toolName)
	}
	if _, ok := locked.Platforms[platform.Key(runtime.GOOS, runtime.GOARCH)]; !ok {
		return "", fmt.Errorf("tool %q lock entry missing platform %s", toolName, platform.Key(runtime.GOOS, runtime.GOARCH))
	}

	// Keep naming deterministic and simple in v1.
	binaryName := toolName
	return InstallPath(baseDir, componenttypes.KindTool, toolName, locked.Version, binaryName)
}

// ResolveRemoteBinaryPath resolves a remote adapter binary path from config + lockfile.
// For source-based remotes, it returns deterministic install path.
// For external remotes, it returns the configured absolute binary path.
// For adapter-only remotes (no source or binary), it returns empty string (use PATH discovery).
func ResolveRemoteBinaryPath(baseDir, remoteName string, cfg config.RemoteConfig, lf *lockfile.LockFile) (string, error) {
	// Adapter-only mode - no managed binary, use PATH discovery
	if cfg.Source == "" && cfg.Binary == "" {
		return "", nil
	}

	if cfg.Binary != "" {
		if !filepath.IsAbs(cfg.Binary) {
			return "", fmt.Errorf("remote %q binary must be absolute path", remoteName)
		}
		return cfg.Binary, nil
	}

	locked, ok := lf.GetRemote(remoteName)
	if !ok {
		return "", fmt.Errorf("remote %q not found in lockfile", remoteName)
	}
	if locked.Version == "" {
		return "", fmt.Errorf("remote %q lock entry missing version", remoteName)
	}
	if _, ok := locked.Platforms[platform.Key(runtime.GOOS, runtime.GOARCH)]; !ok {
		return "", fmt.Errorf("remote %q lock entry missing platform %s", remoteName, platform.Key(runtime.GOOS, runtime.GOARCH))
	}

	adapterName := cfg.EffectiveAdapter()
	if adapterName == "" {
		return "", fmt.Errorf("remote %q has no adapter name", remoteName)
	}

	return InstallPath(baseDir, componenttypes.KindRemote, remoteName, locked.Version, adapterName)
}
