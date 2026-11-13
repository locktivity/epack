//go:build components

package sdkcmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/catalog"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/surface"
	"github.com/locktivity/epack/internal/tracemap"
	"github.com/spf13/cobra"
)

var (
	surfaceSpecs      []string
	surfaceConfig     string
	surfaceRecordings string
	surfaceDocs       string
	surfaceCheck      bool
	surfaceWrite      bool
	surfaceVerbose    bool
)

func newSurfaceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "surface [directory]",
		Short: "Compare a collector's recordings with the vendor's API description",
		Long: `Compare the vendor API calls in a collector's recordings with the vendor's
OpenAPI description, so what the collector reads and what it leaves out
comes from the vendor rather than from memory.

The command matches each recorded request to an operation of the
description. Every in-scope operation the recordings never call needs a
verdict in docs/surface.yaml: not collected, with the sentence the
documentation shows, or irrelevant, with the reason. Only GET operations
are in scope unless surface.yaml says otherwise. Recorded requests the
description does not describe, such as a token endpoint or a GraphQL
query, are acknowledged under unmatched.

A description is read from --spec, from the file an entry of surface.yaml
names, or fetched from the url it names, pinned to a revision and checked
against its sha256, into epack's cache, so CI needs no local copy.

Two documents are rendered from the verdicts. The Not Collected section
of docs/overview.md shows the overview headlines in surface.yaml, each
folding one or more items into a sentence a buyer needs, and points at the
coverage reference. The reference, docs/coverage.md by default, leads with
what the collector reads by area, then holds every item with its
operations, the calls the sandbox never exercises, what is left out as
irrelevant, and the recorded calls outside the description. --write puts
both in place, and --check fails when either differs from the verdicts,
when an operation lacks a verdict, when a verdict names an operation the
recordings call or the description lacks, or when a recorded request is
neither described nor acknowledged.

Examples:
  epack sdk surface --spec ~/specs/okta/management.yaml
  epack sdk surface --spec api.github.com.json --write
  epack sdk surface --check`,
		Args: cobra.MaximumNArgs(1),
		RunE: runSurface,
	}
	cmd.Flags().StringArrayVar(&surfaceSpecs, "spec", nil, "the vendor's OpenAPI description, JSON or YAML; repeat it for several, one per entry of specs in surface.yaml (default: the file each entry names)")
	cmd.Flags().StringVar(&surfaceConfig, "surface", surface.DefaultConfigFile, "the verdicts file, relative to the module root")
	cmd.Flags().StringVar(&surfaceRecordings, "recordings", surface.DefaultRecordingsDir, "the recordings directory, relative to the module root")
	cmd.Flags().StringVar(&surfaceDocs, "docs", "docs/overview.md", "the overview whose Not Collected section is rendered, relative to the module root")
	cmd.Flags().BoolVar(&surfaceCheck, "check", false, "fail on a missing or stale verdict or a stale Not Collected section, without writing")
	cmd.Flags().BoolVar(&surfaceWrite, "write", false, "write the Not Collected section into the overview")
	cmd.Flags().BoolVarP(&surfaceVerbose, "verbose", "v", false, "list every exercised operation and every verdict")
	return cmd
}

func runSurface(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	p := out.Palette()
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	root, ok := tracemap.FindModuleRoot(dir)
	if !ok {
		return fmt.Errorf("%s is not inside a Go module", dir)
	}
	for _, rel := range []string{surfaceConfig, surfaceRecordings, surfaceDocs} {
		if filepath.IsAbs(rel) || strings.HasPrefix(filepath.Clean(rel), "..") {
			return fmt.Errorf("%s must be a path inside the module", rel)
		}
	}
	cfg, err := surface.LoadConfig(root, surfaceConfig)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s does not exist; create it with vendor, spec and scope, then run the command for the verdicts it needs", surfaceConfig)
		}
		return err
	}
	refs := cfg.Descriptions()
	specPaths := surfaceSpecs
	if len(specPaths) == 0 {
		var cacheDir string
		for _, ref := range refs {
			switch {
			case ref.File != "":
				specPaths = append(specPaths, filepath.Join(root, filepath.FromSlash(ref.File)))
			case ref.URL != "":
				if cacheDir == "" {
					if cacheDir, err = catalog.Dir(); err != nil {
						return err
					}
				}
				fetched, err := surface.Fetch(cmd.Context(), ref, cacheDir, nil)
				if err != nil {
					return err
				}
				out.Verbose("Fetched %s to %s", ref.Label(), fetched)
				specPaths = append(specPaths, fetched)
			default:
				return fmt.Errorf("pass --spec for %s, or give it a file or url in %s", ref.Label(), surfaceConfig)
			}
		}
		if len(specPaths) == 0 {
			return fmt.Errorf("pass --spec, or set spec.file or spec.url in %s", surfaceConfig)
		}
	}
	if len(refs) > 1 && len(specPaths) != len(refs) {
		return fmt.Errorf("%s pins %d descriptions, so pass --spec %d times, in their order", surfaceConfig, len(refs), len(refs))
	}
	for i, specPath := range specPaths {
		if i >= len(refs) || refs[i].SHA256 == "" {
			continue
		}
		got, err := surface.Digest(specPath)
		if err != nil {
			return err
		}
		if !strings.EqualFold(got, refs[i].SHA256) {
			return fmt.Errorf("%s has digest %s, and %s pins %s for %s; refresh the verdicts against the new description, then update its sha256 and revision", specPath, got, surfaceConfig, refs[i].SHA256, refs[i].Label())
		}
	}
	spec, err := surface.LoadSpecs(specPaths)
	if err != nil {
		return err
	}
	for i, part := range spec.Parts {
		if i < len(refs) && refs[i].Name != "" {
			part.Rename(refs[i].Name)
		}
	}
	if len(spec.Parts) == 0 && len(refs) == 1 && refs[0].Name != "" {
		spec.Rename(refs[0].Name)
	}
	calls, err := surface.LoadCalls(root, surfaceRecordings)
	if err != nil {
		return err
	}
	report := surface.Analyze(spec, cfg, calls)

	out.Section("API description")
	out.KeyValue("Operations", fmt.Sprintf("%d, %d in scope, %d deprecated", report.SpecOperations, report.InScope, report.Deprecated))
	for _, part := range spec.Parts {
		out.KeyValue("  "+part.Name, fmt.Sprintf("%d operations", len(part.Operations)))
	}
	out.KeyValue("Recorded requests", fmt.Sprintf("%d, from %d collector operations", len(calls), countOperations(calls)))

	out.Section(fmt.Sprintf("Exercised: %d operations", len(report.Exercised)))
	if surfaceVerbose {
		for _, e := range report.Exercised {
			out.Print("  %-48s %s %s  %s\n", e.Op.Key(), e.Op.Method, e.Op.Path, p.Dim(e.CollectorNames()))
		}
	}
	if len(report.Acknowledged) > 0 {
		out.Section(fmt.Sprintf("Outside the description, acknowledged: %d", len(report.Acknowledged)))
		for _, c := range report.Acknowledged {
			out.Print("  %-40s %s %s\n", c.Operation, c.Method, pathOnly(c.URL))
		}
	}
	if len(report.Unmatched) > 0 {
		out.Section(fmt.Sprintf("Outside the description, unacknowledged: %d", len(report.Unmatched)))
		for _, c := range report.Unmatched {
			out.Print("  %s %-40s %s %s\n", p.Yellow("!"), c.Operation, c.Method, pathOnly(c.URL))
		}
	}

	out.Section(fmt.Sprintf("Not collected: %d operations in %d items", len(report.NotCollected), len(cfg.NotCollected)))
	if surfaceVerbose {
		printVerdicts(out, report.NotCollected)
	}
	out.Section(fmt.Sprintf("Irrelevant: %d operations in %d items", len(report.Irrelevant), len(cfg.Irrelevant)))
	if surfaceVerbose {
		printVerdicts(out, report.Irrelevant)
	}
	if len(report.Reads) > 0 {
		out.Section(fmt.Sprintf("Read, but no recording holds the call: %d operations", len(report.Reads)))
		for _, g := range report.Reads {
			out.Print("  %s %-48s %s %s  %s\n", p.Yellow("~"), g.Op.Key(), g.Op.Method, g.Op.Path, p.Dim(g.Read.Collector+": when "+g.Read.When))
		}
	}
	if len(report.Unverdicted) > 0 {
		out.Section(fmt.Sprintf("No verdict: %d operations", len(report.Unverdicted)))
		for _, op := range report.Unverdicted {
			out.Print("  %s %-48s %s %s  %s\n", p.Yellow("?"), op.Key(), op.Method, op.Path, p.Dim(strings.Join(op.Tags, ", ")+"  "+op.Summary))
		}
	}

	info := surface.Docs{Module: modulePath(root)}
	section := surface.RenderSection(cfg, info)
	docs, err := safefile.ReadFileBeneath(root, surfaceDocs, limits.Artifact)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	reference := surface.RenderReference(cfg, report, info)
	referenceFile := filepath.FromSlash(cfg.Reference.File)
	if filepath.IsAbs(referenceFile) || strings.HasPrefix(filepath.Clean(referenceFile), "..") {
		return fmt.Errorf("reference.file %s must be a path inside the module", cfg.Reference.File)
	}
	currentReference, err := safefile.ReadFileBeneath(root, referenceFile, limits.Artifact)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staleSection := surface.CurrentSection(docs) != section
	staleReference := string(currentReference) != reference
	switch {
	case surfaceWrite:
		if staleSection {
			if err := safefile.WriteFile(root, surfaceDocs, surface.ReplaceSection(docs, section)); err != nil {
				return err
			}
			out.Success("Wrote the Not Collected section of %s", surfaceDocs)
		} else {
			out.Print("%s The Not Collected section of %s is current\n", p.Green("✓"), surfaceDocs)
		}
		if staleReference {
			if err := safefile.WriteFile(root, referenceFile, []byte(reference)); err != nil {
				return err
			}
			out.Success("Wrote the coverage reference %s", cfg.Reference.File)
		} else {
			out.Print("%s The coverage reference %s is current\n", p.Green("✓"), cfg.Reference.File)
		}
	default:
		if staleSection {
			report.Problems = append(report.Problems, fmt.Sprintf("the Not Collected section of %s differs from the verdicts; run the command with --write", surfaceDocs))
		}
		if staleReference {
			report.Problems = append(report.Problems, fmt.Sprintf("the coverage reference %s differs from the verdicts; run the command with --write", cfg.Reference.File))
		}
	}

	if len(report.Problems) > 0 {
		out.Section(fmt.Sprintf("Problems: %d", len(report.Problems)))
		for _, problem := range report.Problems {
			out.Print("  %s %s\n", p.Red("✗"), problem)
		}
		if surfaceCheck {
			return fmt.Errorf("the surface check found %d problems", len(report.Problems))
		}
		return nil
	}
	out.Success("Every in-scope operation has a verdict")
	return nil
}

func printVerdicts(out interface{ Print(string, ...interface{}) }, verdicts []surface.Verdict) {
	for _, v := range verdicts {
		out.Print("  %-48s %s %s  %s\n", v.Op.Key(), v.Op.Method, v.Op.Path, v.Item.Label())
	}
}

// modulePath reads the module line of the module's go.mod.
func modulePath(root string) string {
	data, err := safefile.ReadFileBeneath(root, "go.mod", limits.ConfigFile)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), "\"")
		}
	}
	return ""
}

func countOperations(calls []surface.Call) int {
	seen := map[string]bool{}
	for _, c := range calls {
		seen[c.Operation] = true
	}
	return len(seen)
}

func pathOnly(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rawURL = rawURL[i+3:]
		if j := strings.Index(rawURL, "/"); j >= 0 {
			rawURL = rawURL[j:]
		}
	}
	if i := strings.Index(rawURL, "?"); i >= 0 {
		rawURL = rawURL[:i]
	}
	return rawURL
}
