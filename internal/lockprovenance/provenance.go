package lockprovenance

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/buildcontext"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
)

const (
	TriggerBootstrap   = "bootstrap"
	TriggerRefresh     = "refresh"
	TriggerFrozenCheck = "frozen_check"

	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

type Options struct {
	ProjectRoot    string
	TriggerKind    string
	Outcome        string
	FailureCode    string
	FailureMessage string
	ReportedAt     time.Time
	Getenv         func(string) string
}

type Provenance struct {
	Lockfile       string         `json:"lockfile,omitempty"`
	LockfileSHA256 string         `json:"lockfile_sha256,omitempty"`
	LockfilePath   string         `json:"lockfile_path,omitempty"`
	Summary        Summary        `json:"summary,omitempty"`
	RuntimeContext map[string]any `json:"runtime_context,omitempty"`
	TriggerKind    string         `json:"trigger_kind"`
	Outcome        string         `json:"outcome"`
	FailureCode    string         `json:"failure_code,omitempty"`
	FailureMessage string         `json:"failure_message,omitempty"`
	ReportedAt     string         `json:"reported_at,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type Summary struct {
	SchemaVersion int                `json:"schema_version,omitempty"`
	Collectors    []ComponentSummary `json:"collectors,omitempty"`
	Tools         []ComponentSummary `json:"tools,omitempty"`
	Remotes       []ComponentSummary `json:"remotes,omitempty"`
	Profiles      []FileSummary      `json:"profiles,omitempty"`
	Overlays      []FileSummary      `json:"overlays,omitempty"`
}

type ComponentSummary struct {
	Name         string                       `json:"name"`
	Kind         string                       `json:"kind,omitempty"`
	Source       string                       `json:"source,omitempty"`
	Version      string                       `json:"version,omitempty"`
	Commit       string                       `json:"commit,omitempty"`
	Signer       *componenttypes.LockedSigner `json:"signer,omitempty"`
	ResolvedFrom *componenttypes.ResolvedFrom `json:"resolved_from,omitempty"`
	Verification *componenttypes.Verification `json:"verification,omitempty"`
	LockedAt     string                       `json:"locked_at,omitempty"`
	Platforms    []PlatformSummary            `json:"platforms,omitempty"`
}

type PlatformSummary struct {
	Name   string `json:"name"`
	Digest string `json:"digest,omitempty"`
	Asset  string `json:"asset,omitempty"`
	URL    string `json:"url,omitempty"`
}

type FileSummary struct {
	Name     string                       `json:"name"`
	Source   string                       `json:"source,omitempty"`
	Version  string                       `json:"version,omitempty"`
	Digest   string                       `json:"digest,omitempty"`
	Signer   *componenttypes.LockedSigner `json:"signer,omitempty"`
	LockedAt string                       `json:"locked_at,omitempty"`
}

func Build(opts Options) (*Provenance, error) {
	opts = normalizeOptions(opts)
	if err := validateTrigger(opts.TriggerKind); err != nil {
		return nil, err
	}
	if err := validateOutcome(opts); err != nil {
		return nil, err
	}
	if opts.Outcome == OutcomeFailure {
		return failureProvenance(opts), nil
	}

	lockPath := filepath.Join(opts.ProjectRoot, lockfile.FileName)
	raw, err := safefile.ReadFile(lockPath, limits.LockFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", lockfile.FileName, err)
	}
	lf, err := lockfile.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", lockfile.FileName, err)
	}

	digest := sha256.Sum256(raw)
	return &Provenance{
		Lockfile:       string(raw),
		LockfileSHA256: fmt.Sprintf("%x", digest[:]),
		LockfilePath:   lockfile.FileName,
		Summary:        summarize(lf),
		RuntimeContext: runtimeContext(opts.Getenv),
		TriggerKind:    opts.TriggerKind,
		Outcome:        OutcomeSuccess,
		ReportedAt:     opts.ReportedAt.UTC().Format(time.RFC3339),
	}, nil
}

func normalizeOptions(opts Options) Options {
	if opts.ProjectRoot == "" {
		opts.ProjectRoot = "."
	}
	if opts.TriggerKind == "" {
		opts.TriggerKind = TriggerFrozenCheck
	}
	if opts.Outcome == "" {
		opts.Outcome = OutcomeSuccess
	}
	if opts.ReportedAt.IsZero() {
		opts.ReportedAt = time.Now()
	}
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	return opts
}

func validateTrigger(trigger string) error {
	switch trigger {
	case TriggerBootstrap, TriggerRefresh, TriggerFrozenCheck:
		return nil
	default:
		return fmt.Errorf("invalid trigger kind %q", trigger)
	}
}

func validateOutcome(opts Options) error {
	switch opts.Outcome {
	case OutcomeSuccess:
		return nil
	case OutcomeFailure:
		if strings.TrimSpace(opts.FailureCode) == "" {
			return fmt.Errorf("failure_code is required for failed lock reports")
		}
		return nil
	default:
		return fmt.Errorf("invalid outcome %q", opts.Outcome)
	}
}

func failureProvenance(opts Options) *Provenance {
	return &Provenance{
		RuntimeContext: runtimeContext(opts.Getenv),
		TriggerKind:    opts.TriggerKind,
		Outcome:        OutcomeFailure,
		FailureCode:    opts.FailureCode,
		FailureMessage: opts.FailureMessage,
		ReportedAt:     opts.ReportedAt.UTC().Format(time.RFC3339),
	}
}

func runtimeContext(getenv func(string) string) map[string]any {
	if ctx := buildcontext.Build(getenv); ctx != nil {
		return ctx.ToMap()
	}
	return nil
}

func summarize(lf *lockfile.LockFile) Summary {
	return Summary{
		SchemaVersion: lf.SchemaVersion,
		Collectors:    summarizeCollectors(lf.Collectors),
		Tools:         summarizeTools(lf.Tools),
		Remotes:       summarizeRemotes(lf.Remotes),
		Profiles:      summarizeProfiles(lf.Profiles),
		Overlays:      summarizeOverlays(lf.Overlays),
	}
}

func summarizeCollectors(entries map[string]lockfile.LockedCollector) []ComponentSummary {
	names := sortedNames(entries)
	out := make([]ComponentSummary, 0, len(names))
	for _, name := range names {
		entry := entries[name]
		out = append(out, ComponentSummary{
			Name:         name,
			Kind:         entry.Kind,
			Source:       entry.Source,
			Version:      entry.Version,
			Commit:       entry.Commit,
			Signer:       entry.Signer,
			ResolvedFrom: entry.ResolvedFrom,
			Verification: entry.Verification,
			LockedAt:     entry.LockedAt,
			Platforms:    summarizePlatforms(entry.Platforms),
		})
	}
	return out
}

func summarizeTools(entries map[string]lockfile.LockedTool) []ComponentSummary {
	names := sortedNames(entries)
	out := make([]ComponentSummary, 0, len(names))
	for _, name := range names {
		entry := entries[name]
		out = append(out, ComponentSummary{
			Name:         name,
			Kind:         entry.Kind,
			Source:       entry.Source,
			Version:      entry.Version,
			Commit:       entry.Commit,
			Signer:       entry.Signer,
			ResolvedFrom: entry.ResolvedFrom,
			Verification: entry.Verification,
			LockedAt:     entry.LockedAt,
			Platforms:    summarizePlatforms(entry.Platforms),
		})
	}
	return out
}

func summarizeRemotes(entries map[string]lockfile.LockedRemote) []ComponentSummary {
	names := sortedNames(entries)
	out := make([]ComponentSummary, 0, len(names))
	for _, name := range names {
		entry := entries[name]
		out = append(out, ComponentSummary{
			Name:         name,
			Kind:         entry.Kind,
			Source:       entry.Source,
			Version:      entry.Version,
			Commit:       entry.Commit,
			Signer:       entry.Signer,
			ResolvedFrom: entry.ResolvedFrom,
			Verification: entry.Verification,
			LockedAt:     entry.LockedAt,
			Platforms:    summarizePlatforms(entry.Platforms),
		})
	}
	return out
}

func summarizeProfiles(entries map[string]lockfile.LockedProfile) []FileSummary {
	names := sortedNames(entries)
	out := make([]FileSummary, 0, len(names))
	for _, name := range names {
		entry := entries[name]
		out = append(out, FileSummary{
			Name:     name,
			Source:   entry.Source,
			Version:  entry.Version,
			Digest:   entry.Digest,
			Signer:   entry.Signer,
			LockedAt: entry.LockedAt,
		})
	}
	return out
}

func summarizeOverlays(entries map[string]lockfile.LockedOverlay) []FileSummary {
	names := sortedNames(entries)
	out := make([]FileSummary, 0, len(names))
	for _, name := range names {
		entry := entries[name]
		out = append(out, FileSummary{
			Name:     name,
			Source:   entry.Source,
			Version:  entry.Version,
			Digest:   entry.Digest,
			Signer:   entry.Signer,
			LockedAt: entry.LockedAt,
		})
	}
	return out
}

func summarizePlatforms(entries map[string]componenttypes.LockedPlatform) []PlatformSummary {
	names := sortedNames(entries)
	out := make([]PlatformSummary, 0, len(names))
	for _, name := range names {
		entry := entries[name]
		out = append(out, PlatformSummary{
			Name:   name,
			Digest: entry.Digest,
			Asset:  entry.Asset,
			URL:    entry.URL,
		})
	}
	return out
}

func sortedNames[T any](entries map[string]T) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
