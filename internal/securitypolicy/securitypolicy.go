package securitypolicy

import (
	"fmt"
	"os"

	"github.com/locktivity/epack/internal/securityaudit"
)

// ExecutionPolicy captures execution-time security mode for components that may
// allow unpinned execution.
type ExecutionPolicy struct {
	Frozen        bool
	AllowUnpinned bool
}

// Enforce validates policy invariants.
func (p ExecutionPolicy) Enforce() error {
	if p.Frozen && p.AllowUnpinned {
		return fmt.Errorf("--insecure-allow-unpinned cannot be used with --frozen")
	}
	return nil
}

// ValidateRemoteExecution is a compatibility wrapper around ExecutionPolicy.
func ValidateRemoteExecution(frozen, insecureAllowUnpinned bool) error {
	return ExecutionPolicy{
		Frozen:        frozen,
		AllowUnpinned: insecureAllowUnpinned,
	}.Enforce()
}

// StrictProductionEnvVar enables strict production mode when set to true/1.
const StrictProductionEnvVar = "EPACK_STRICT_PRODUCTION"

// StrictProductionEnabled returns true when strict production mode is enabled.
func StrictProductionEnabled() bool {
	v := os.Getenv(StrictProductionEnvVar)
	return v == "1" || v == "true"
}

// EnforceStrictProduction blocks insecure execution overrides in strict production mode.
func EnforceStrictProduction(component string, hasUnsafeOverrides bool) error {
	if !StrictProductionEnabled() || !hasUnsafeOverrides {
		return nil
	}
	securityaudit.Emit(securityaudit.Event{
		Type:        securityaudit.EventInsecureBypass,
		Component:   component,
		Description: "strict production mode blocked insecure override",
		Attrs: map[string]string{
			"strict_mode": "true",
		},
	})
	return fmt.Errorf("strict production mode forbids insecure execution overrides for %s", component)
}
