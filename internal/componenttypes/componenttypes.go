// Package componenttypes defines shared types for component management.
// These types are used across lockfile, userconfig, catalog, and conformance packages
// to provide a consistent interface for component metadata.
package componenttypes

// ComponentKind identifies the type of component.
type ComponentKind string

const (
	KindCollector ComponentKind = "collector"
	KindTool      ComponentKind = "tool"
	KindRemote    ComponentKind = "remote"
	KindUtility   ComponentKind = "utility"
)

// String implements fmt.Stringer.
func (k ComponentKind) String() string {
	return string(k)
}

// Plural returns the plural form used in paths (collectors/tools/remotes/utilities).
func (k ComponentKind) Plural() string {
	switch k {
	case KindCollector:
		return "collectors"
	case KindTool:
		return "tools"
	case KindRemote:
		return "remotes"
	case KindUtility:
		return "utilities"
	default:
		return string(k) + "s"
	}
}

// LockedSigner captures required source signer identity claims.
type LockedSigner struct {
	Issuer              string `yaml:"issuer" json:"issuer"`
	Subject             string `yaml:"subject,omitempty" json:"subject,omitempty"`
	SourceRepositoryURI string `yaml:"source_repository_uri" json:"source_repository_uri"`
	SourceRepositoryRef string `yaml:"source_repository_ref" json:"source_repository_ref"`
}

// LockedPlatform pins per-platform digest information.
type LockedPlatform struct {
	Digest string `yaml:"digest" json:"digest"`
	Asset  string `yaml:"asset,omitempty" json:"asset,omitempty"`
	URL    string `yaml:"url,omitempty" json:"url,omitempty"`
}

// ResolvedFrom captures where the component was resolved from.
type ResolvedFrom struct {
	Registry   string `yaml:"registry,omitempty" json:"registry,omitempty"`
	Descriptor string `yaml:"descriptor,omitempty" json:"descriptor,omitempty"`
}

// Verification captures the verification state at lock time.
type Verification struct {
	Status     string `yaml:"status,omitempty" json:"status,omitempty"`
	VerifiedAt string `yaml:"verified_at,omitempty" json:"verified_at,omitempty"`
}

// LockedUtility pins a user-installed utility.
// Utilities are global user tools installed via `epack install utility`.
// They use the same supply chain security model as other components.
type LockedUtility struct {
	Source       string                    `yaml:"source,omitempty"`
	Version      string                    `yaml:"version,omitempty"`
	Signer       *LockedSigner             `yaml:"signer,omitempty"`
	ResolvedFrom *ResolvedFrom             `yaml:"resolved_from,omitempty"`
	Verification *Verification             `yaml:"verification,omitempty"`
	LockedAt     string                    `yaml:"locked_at,omitempty"`
	Platforms    map[string]LockedPlatform `yaml:"platforms"`
}

// CopySigner creates a defensive copy of a LockedSigner pointer.
func CopySigner(src *LockedSigner) *LockedSigner {
	if src == nil {
		return nil
	}
	cp := *src
	return &cp
}

// CopyResolvedFrom creates a defensive copy of a ResolvedFrom pointer.
func CopyResolvedFrom(src *ResolvedFrom) *ResolvedFrom {
	if src == nil {
		return nil
	}
	cp := *src
	return &cp
}

// CopyVerification creates a defensive copy of a Verification pointer.
func CopyVerification(src *Verification) *Verification {
	if src == nil {
		return nil
	}
	cp := *src
	return &cp
}

// CopyPlatforms creates a defensive copy of a platforms map.
func CopyPlatforms(src map[string]LockedPlatform) map[string]LockedPlatform {
	if src == nil {
		return nil
	}
	dst := make(map[string]LockedPlatform, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
