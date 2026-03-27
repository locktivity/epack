package hooks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/procexec"
	"github.com/locktivity/epack/internal/project"
)

var hookNamePattern = regexp.MustCompile(`^(?:[a-z0-9]|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)$`)

// Runner executes portable project hooks from .epack/hooks.
type Runner struct {
	WorkDir string
	Stdout  io.Writer
	Stderr  io.Writer
	Timeout time.Duration
}

// Run executes the named hook via sh and returns nil when the hook is missing or empty.
func (r Runner) Run(ctx context.Context, hook string) error {
	if !hookNamePattern.MatchString(hook) {
		return fmt.Errorf("invalid hook name %q", hook)
	}
	projectRoot, err := r.projectRoot()
	if err != nil {
		return err
	}
	scriptPath := filepath.Join(projectRoot, ".epack", "hooks", hook+".sh")
	info, err := os.Stat(scriptPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("checking hook %q: %w", hook, err)
	}
	if info.IsDir() {
		return fmt.Errorf("hook %q is a directory", hook)
	}
	if info.Size() == 0 {
		return nil
	}

	timeout := r.effectiveTimeout()
	hookCtx, cancel := context.WithTimeout(contextOrBackground(ctx), timeout)
	defer cancel()

	err = procexec.Run(hookCtx, procexec.Spec{
		Path:   "sh",
		Args:   []string{scriptPath},
		Dir:    projectRoot,
		Env:    os.Environ(),
		Stdout: r.Stdout,
		Stderr: r.Stderr,
	})
	if err != nil && errors.Is(hookCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("hook %q timed out after %s", hook, timeout)
	}
	return err
}

func (r Runner) projectRoot() (string, error) {
	start := r.WorkDir
	if start == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("getting working directory: %w", err)
		}
	}
	if root, err := project.FindRoot(start); err == nil {
		return root, nil
	}
	return filepath.Abs(start)
}

func (r Runner) effectiveTimeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return limits.DefaultHookTimeout
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
}
