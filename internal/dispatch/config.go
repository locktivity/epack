package dispatch

import (
	"fmt"
	"path/filepath"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/project"
)

// configLoadError indicates a configuration loading error that distinguishes
// between "not found" (allows PATH fallback) vs "parse/validation error" (should fail).
type configLoadError struct {
	notFound bool // true if epack.yaml not found (allows PATH fallback)
	err      error
}

func (e *configLoadError) Error() string {
	return e.err.Error()
}

// loadToolConfig attempts to load epack.yaml and lockfile, returning tool config if found.
// Searches upward from workDir to find project root (directory containing epack.yaml).
// Returns a *configLoadError with notFound=true if epack.yaml doesn't exist (allows PATH fallback).
// Returns other errors for parse/validation failures (should fail, not fallback).
func loadToolConfig(workDir, toolName string) (config.ToolConfig, *lockfile.LockFile, error) {
	// Search upward for epack.yaml
	projectRoot, err := project.FindRoot(workDir)
	if err != nil {
		// epack.yaml not found - allow PATH fallback
		return config.ToolConfig{}, nil, &configLoadError{notFound: true, err: err}
	}

	configPath := filepath.Join(projectRoot, "epack.yaml")
	lockfilePath := filepath.Join(projectRoot, lockfile.FileName)

	cfg, err := config.Load(configPath)
	if err != nil {
		// Config file exists but failed to parse - this is a real error
		return config.ToolConfig{}, nil, &configLoadError{notFound: false, err: fmt.Errorf("loading config: %w", err)}
	}

	toolCfg, ok := cfg.Tools[toolName]
	if !ok {
		// Tool not in config - allow PATH fallback (tool may be external)
		return config.ToolConfig{}, nil, &configLoadError{notFound: true, err: fmt.Errorf("tool %q not configured", toolName)}
	}

	lf, err := lockfile.Load(lockfilePath)
	if err != nil {
		// Lockfile missing or invalid - this is a real error for configured tools
		return config.ToolConfig{}, nil, &configLoadError{notFound: false, err: fmt.Errorf("loading lockfile: %w", err)}
	}

	return toolCfg, lf, nil
}

