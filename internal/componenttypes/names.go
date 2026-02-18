// Package componenttypes defines shared types for component management.
// This file defines type-safe validated names that can only be constructed
// through validation functions, making validation bypass impossible.
package componenttypes

import (
	"encoding/json"
	"fmt"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/validate"
)

// validateName validates a component name for use in filesystem paths.
// SECURITY: Uses centralized validate.ComponentName for consistent checks.
func validateName(name, kind string) error {
	if ok, reason := validate.ComponentName(name, kind); !ok {
		return errors.E(errors.InvalidName, fmt.Sprintf("%s name %q is invalid: %s", kind, name, reason), nil)
	}
	return nil
}

// CollectorName is a validated collector name safe for filesystem paths.
// Can only be constructed via ParseCollectorName.
type CollectorName string

// ParseCollectorName validates and returns a CollectorName.
// Returns an error if the name contains path traversal patterns or invalid characters.
func ParseCollectorName(name string) (CollectorName, error) {
	if err := validateName(name, "collector"); err != nil {
		return "", err
	}
	return CollectorName(name), nil
}

// MustParseCollectorName parses a collector name, panicking on invalid input.
// Use only for compile-time constants or test fixtures.
func MustParseCollectorName(name string) CollectorName {
	n, err := ParseCollectorName(name)
	if err != nil {
		panic(err)
	}
	return n
}

// String returns the collector name as a string.
func (n CollectorName) String() string {
	return string(n)
}

// UnmarshalYAML implements yaml.Unmarshaler with validation.
func (n *CollectorName) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := ParseCollectorName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// UnmarshalJSON implements json.Unmarshaler with validation.
func (n *CollectorName) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseCollectorName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// ToolName is a validated tool name safe for filesystem paths.
// Can only be constructed via ParseToolName.
type ToolName string

// ParseToolName validates and returns a ToolName.
func ParseToolName(name string) (ToolName, error) {
	if err := validateName(name, "tool"); err != nil {
		return "", err
	}
	return ToolName(name), nil
}

// MustParseToolName parses a tool name, panicking on invalid input.
func MustParseToolName(name string) ToolName {
	n, err := ParseToolName(name)
	if err != nil {
		panic(err)
	}
	return n
}

// String returns the tool name as a string.
func (n ToolName) String() string {
	return string(n)
}

// UnmarshalYAML implements yaml.Unmarshaler with validation.
func (n *ToolName) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := ParseToolName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// UnmarshalJSON implements json.Unmarshaler with validation.
func (n *ToolName) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseToolName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// RemoteName is a validated remote name safe for filesystem paths.
// Can only be constructed via ParseRemoteName.
type RemoteName string

// ParseRemoteName validates and returns a RemoteName.
func ParseRemoteName(name string) (RemoteName, error) {
	if err := validateName(name, "remote"); err != nil {
		return "", err
	}
	return RemoteName(name), nil
}

// MustParseRemoteName parses a remote name, panicking on invalid input.
func MustParseRemoteName(name string) RemoteName {
	n, err := ParseRemoteName(name)
	if err != nil {
		panic(err)
	}
	return n
}

// String returns the remote name as a string.
func (n RemoteName) String() string {
	return string(n)
}

// UnmarshalYAML implements yaml.Unmarshaler with validation.
func (n *RemoteName) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := ParseRemoteName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// UnmarshalJSON implements json.Unmarshaler with validation.
func (n *RemoteName) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseRemoteName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// UtilityName is a validated utility name safe for filesystem paths.
// Can only be constructed via ParseUtilityName.
type UtilityName string

// ParseUtilityName validates and returns a UtilityName.
func ParseUtilityName(name string) (UtilityName, error) {
	if err := validateName(name, "utility"); err != nil {
		return "", err
	}
	return UtilityName(name), nil
}

// MustParseUtilityName parses a utility name, panicking on invalid input.
func MustParseUtilityName(name string) UtilityName {
	n, err := ParseUtilityName(name)
	if err != nil {
		panic(err)
	}
	return n
}

// String returns the utility name as a string.
func (n UtilityName) String() string {
	return string(n)
}

// UnmarshalYAML implements yaml.Unmarshaler with validation.
func (n *UtilityName) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := ParseUtilityName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// UnmarshalJSON implements json.Unmarshaler with validation.
func (n *UtilityName) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseUtilityName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// EnvironmentName is a validated environment name safe for filesystem paths.
// Can only be constructed via ParseEnvironmentName.
type EnvironmentName string

// ParseEnvironmentName validates and returns an EnvironmentName.
func ParseEnvironmentName(name string) (EnvironmentName, error) {
	if err := validateName(name, "environment"); err != nil {
		return "", err
	}
	return EnvironmentName(name), nil
}

// MustParseEnvironmentName parses an environment name, panicking on invalid input.
func MustParseEnvironmentName(name string) EnvironmentName {
	n, err := ParseEnvironmentName(name)
	if err != nil {
		panic(err)
	}
	return n
}

// String returns the environment name as a string.
func (n EnvironmentName) String() string {
	return string(n)
}

// UnmarshalYAML implements yaml.Unmarshaler with validation.
func (n *EnvironmentName) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := ParseEnvironmentName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// UnmarshalJSON implements json.Unmarshaler with validation.
func (n *EnvironmentName) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseEnvironmentName(s)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}
