package cmd

import (
	"fmt"
	"os"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/cli/sigstore"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/merge"
	"github.com/spf13/cobra"
)

var (
	mergeStream                        string
	mergeMergedBy                      string
	mergeIncludeAttestations           bool
	mergeForce                         bool
	mergeInsecureSkipAttestationVerify bool
	mergeTrustRoot                     string
	mergeDryRun                        bool
	// Identity policy flags for attestation verification
	mergeIssuer                    string
	mergeSubject                   string
	mergeSubjectRegex              string
	mergeInsecureSkipIdentityCheck bool
)

func init() {
	rootCmd.AddCommand(mergeCmd)

	mergeCmd.Flags().StringVarP(&mergeStream, "stream", "s", "", "stream identifier for merged pack (required)")
	mergeCmd.Flags().StringVar(&mergeMergedBy, "merged-by", "", "identifier of who performed the merge")
	mergeCmd.Flags().BoolVar(&mergeIncludeAttestations, "include-attestations", false, "embed source pack attestations in provenance")
	mergeCmd.Flags().BoolVar(&mergeForce, "force", false, "overwrite existing output file")
	mergeCmd.Flags().BoolVar(&mergeInsecureSkipAttestationVerify, "insecure-skip-attestation-verify", false,
		"INSECURE: skip verification of source pack attestations before embedding")
	mergeCmd.Flags().StringVar(&mergeTrustRoot, "trust-root", "",
		"path to Sigstore trust root JSON file (default: fetch from Sigstore TUF)")
	mergeCmd.Flags().BoolVar(&mergeDryRun, "dry-run", false, "show what would be merged without creating a pack")

	// Identity policy flags for attestation verification
	mergeCmd.Flags().StringVar(&mergeIssuer, "issuer", "",
		"required OIDC issuer for source attestations (e.g., https://accounts.google.com)")
	mergeCmd.Flags().StringVar(&mergeSubject, "subject", "",
		"required exact subject identity for source attestations")
	mergeCmd.Flags().StringVar(&mergeSubjectRegex, "subject-regex", "",
		"required subject pattern (regex) for source attestations")
	mergeCmd.Flags().BoolVar(&mergeInsecureSkipIdentityCheck, "insecure-skip-identity-check", false,
		"INSECURE: accept attestations from any signer (requires explicit opt-in)")

	// Note: --stream is required but we handle it interactively in runMerge
}

var mergeCmd = &cobra.Command{
	Use:        "merge [flags] <output.pack> <source.pack>...",
	Short:      "Merge multiple packs into one",
	SuggestFor: []string{"combine", "join"},
	Long: `Merge combines multiple evidence packs into a single merged pack.

Each source pack's artifacts are included with paths prefixed by the source
pack's stream to avoid collisions. The merged pack includes provenance
metadata documenting which packs were combined.

When --include-attestations is used, source pack attestations are embedded
with cryptographic validation (signature + subject matching). Signer identity
is not verified during merge since the merge operator is untrusted from the
receiver's perspective. Receivers should verify embedded attestations with
their own identity policy:

  epack verify merged.pack --issuer https://accounts.google.com \
                           --subject user@example.com

The merged pack can be signed separately using 'epack sign' to attest to the
merge operation itself.

Examples:
  # Merge two packs
  epack merge combined.pack pack1.pack pack2.pack --stream myorg/combined

  # Merge with attestation preservation (verified by default)
  epack merge combined.pack pack1.pack pack2.pack --stream myorg/combined --include-attestations

  # Merge multiple packs using glob
  epack merge combined.pack ./packs/*.pack --stream myorg/all

  # Skip cryptographic validation (INSECURE)
  epack merge combined.pack pack1.pack pack2.pack --stream myorg/combined --include-attestations --insecure-skip-attestation-verify

  # Specify who performed the merge
  epack merge combined.pack pack1.pack pack2.pack --stream myorg/combined --merged-by "ci-system"

  # Preview what would be merged (dry-run)
  epack merge combined.pack pack1.pack pack2.pack --stream myorg/combined --dry-run`,
	Args: cobra.MinimumNArgs(2),
	RunE: runMerge,
}

func runMerge(cmd *cobra.Command, args []string) error {
	if err := validateMergeFlags(); err != nil {
		return err
	}

	outputPath := args[0]
	sourcePaths := args[1:]
	out := outputWriter()
	ctx := cmdContext(cmd)

	stream, err := resolveMergeStream(out)
	if err != nil {
		return err
	}

	if err := ensureMergeOutputWritable(outputPath); err != nil {
		return err
	}

	sources, err := buildMergeSourceList(sourcePaths)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return exitError("at least one source pack is required")
	}

	// Dry-run mode: show what would be merged without creating a pack
	if mergeDryRun {
		return runMergeDryRun(sources, outputPath, out)
	}

	out.Verbose("Merging %d packs into %s\n", len(sources), outputPath)

	opts := merge.Options{
		Stream:              stream,
		MergedBy:            mergeMergedBy,
		IncludeAttestations: mergeIncludeAttestations,
		VerifyAttestations:  mergeIncludeAttestations && !mergeInsecureSkipAttestationVerify,
	}

	if err := configureMergeVerifier(&opts); err != nil {
		return err
	}

	if err := merge.Merge(ctx, sources, outputPath, opts); err != nil {
		return exitError("failed to merge packs: %v", err)
	}

	return printMergeResult(out, outputPath, stream, sources)
}

func validateMergeFlags() error {
	hasUnsafeOverrides := mergeInsecureSkipAttestationVerify || mergeInsecureSkipIdentityCheck
	if err := securitypolicy.EnforceStrictProduction("merge_cli", hasUnsafeOverrides); err != nil {
		return err
	}
	if hasUnsafeOverrides {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "merge",
			Name:        "merge",
			Description: "merge command running with insecure verification override",
			Attrs: map[string]string{
				"skip_attestation_verify": fmt.Sprintf("%t", mergeInsecureSkipAttestationVerify),
				"skip_identity_check":     fmt.Sprintf("%t", mergeInsecureSkipIdentityCheck),
			},
		})
	}
	return nil
}

// packSummary contains summary information about a pack for dry-run output
type packSummary struct {
	Path         string
	Stream       string
	Artifacts    int
	TotalSize    int64
	Attestations int
}

func runMergeDryRun(sources []merge.SourcePack, outputPath string, out *output.Writer) error {
	summaries, totals, err := collectMergeDryRunSummaries(sources)
	if err != nil {
		return err
	}
	if out.IsJSON() {
		return outputMergeDryRunJSON(out, outputPath, summaries, totals)
	}
	outputMergeDryRunHuman(out, sources, outputPath, summaries, totals)
	return nil
}

type mergeDryRunTotals struct {
	Artifacts    int
	Size         int64
	Attestations int
}

func collectMergeDryRunSummaries(sources []merge.SourcePack) ([]packSummary, mergeDryRunTotals, error) {
	summaries := make([]packSummary, 0, len(sources))
	var totals mergeDryRunTotals
	for _, src := range sources {
		summary, err := summarizeSourcePack(src)
		if err != nil {
			return nil, mergeDryRunTotals{}, err
		}
		summaries = append(summaries, summary)
		totals.Artifacts += summary.Artifacts
		totals.Size += summary.TotalSize
		totals.Attestations += summary.Attestations
	}
	return summaries, totals, nil
}

func summarizeSourcePack(src merge.SourcePack) (packSummary, error) {
	p, err := pack.Open(src.Path)
	if err != nil {
		return packSummary{}, exitError("failed to open pack %s: %v", src.Path, err)
	}
	defer func() { _ = p.Close() }() // Error intentionally ignored in dry-run preview

	manifest := p.Manifest()
	artifactCount, packSize := summarizeEmbeddedArtifacts(manifest.Artifacts)
	return packSummary{
		Path:         src.Path,
		Stream:       manifest.Stream,
		Artifacts:    artifactCount,
		TotalSize:    packSize,
		Attestations: len(p.ListAttestations()),
	}, nil
}

func summarizeEmbeddedArtifacts(artifacts []pack.Artifact) (int, int64) {
	count := 0
	var total int64
	for _, artifact := range artifacts {
		if artifact.Type != "embedded" {
			continue
		}
		count++
		if artifact.Size != nil {
			size, _ := artifact.Size.Int64()
			total += size
		}
	}
	return count, total
}

func outputMergeDryRunJSON(out *output.Writer, outputPath string, summaries []packSummary, totals mergeDryRunTotals) error {
	sourceList := make([]map[string]interface{}, len(summaries))
	for i, s := range summaries {
		sourceList[i] = map[string]interface{}{
			"path":         s.Path,
			"stream":       s.Stream,
			"artifacts":    s.Artifacts,
			"size":         s.TotalSize,
			"attestations": s.Attestations,
		}
	}
	return out.JSON(map[string]interface{}{
		"dry_run":              true,
		"output":               outputPath,
		"stream":               mergeStream,
		"source_packs":         sourceList,
		"total_artifacts":      totals.Artifacts,
		"total_size":           totals.Size,
		"total_attestations":   totals.Attestations,
		"include_attestations": mergeIncludeAttestations,
	})
}

func outputMergeDryRunHuman(out *output.Writer, sources []merge.SourcePack, outputPath string, summaries []packSummary, totals mergeDryRunTotals) {
	palette := out.Palette()
	out.Print("Would merge %d pack(s) into %s\n\n", len(sources), outputPath)
	out.Print("  Stream: %s\n", mergeStream)
	if mergeMergedBy != "" {
		out.Print("  Merged by: %s\n", mergeMergedBy)
	}
	out.Print("\n")

	out.Print("%s\n", palette.Bold("Source packs:"))
	for _, s := range summaries {
		out.Print("  %s\n", s.Path)
		out.Print("    Stream: %s\n", palette.Dim(s.Stream))
		out.Print("    Artifacts: %d (%s)\n", s.Artifacts, output.FormatBytes(s.TotalSize))
		printDryRunAttestationSummary(out, s.Attestations)
	}

	out.Print("\n")
	out.Print("%s\n", palette.Bold("Result:"))
	out.Print("  Total artifacts: %d\n", totals.Artifacts)
	out.Print("  Total size: %s\n", output.FormatBytes(totals.Size))
	if mergeIncludeAttestations {
		out.Print("  Attestations: %d (will be embedded)\n", totals.Attestations)
	}
}

func printDryRunAttestationSummary(out *output.Writer, count int) {
	if count == 0 {
		return
	}
	if mergeIncludeAttestations {
		out.Print("    Attestations: %d (will be embedded)\n", count)
		return
	}
	out.Print("    Attestations: %d (will NOT be embedded, use --include-attestations)\n", count)
}

func resolveMergeStream(out *output.Writer) (string, error) {
	if mergeStream != "" {
		return mergeStream, nil
	}
	if out.IsTTY() && !out.IsJSON() {
		s, err := out.PromptRequired("Stream identifier (e.g., myorg/merged): ")
		if err != nil {
			return "", exitError("--stream is required")
		}
		return s, nil
	}
	return "", exitError("--stream is required")
}

func ensureMergeOutputWritable(outputPath string) error {
	if mergeForce || mergeDryRun {
		return nil
	}
	if _, err := os.Stat(outputPath); err == nil {
		return exitError("output file %q already exists (use --force to overwrite)", outputPath)
	}
	return nil
}

func buildMergeSourceList(sourcePaths []string) ([]merge.SourcePack, error) {
	sources := make([]merge.SourcePack, 0, len(sourcePaths))
	for _, path := range sourcePaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, exitError("source pack not found: %s", path)
		}
		sources = append(sources, merge.SourcePack{Path: path})
	}
	return sources, nil
}

func configureMergeVerifier(opts *merge.Options) error {
	if !opts.VerifyAttestations {
		return nil
	}
	hasIdentityPolicy := mergeIssuer != "" || mergeSubject != "" || mergeSubjectRegex != ""
	if !hasIdentityPolicy && !mergeInsecureSkipIdentityCheck {
		return exitError("--include-attestations requires identity policy (--issuer, --subject, --subject-regex) " +
			"or explicit --insecure-skip-identity-check to accept attestations from any signer")
	}

	cfg := sigstore.VerifierConfig{
		TrustRootPath: mergeTrustRoot,
		Identity: sigstore.IdentityPolicy{
			Issuer:        mergeIssuer,
			Subject:       mergeSubject,
			SubjectRegexp: mergeSubjectRegex,
		},
		InsecureSkipIdentityCheck: mergeInsecureSkipIdentityCheck,
	}
	verifier, err := sigstore.NewVerifier(cfg)
	if err != nil {
		return exitError("failed to create verifier: %v", err)
	}
	opts.Verifier = verifier
	return nil
}

func printMergeResult(out *output.Writer, outputPath, stream string, sources []merge.SourcePack) error {
	if out.IsJSON() {
		sourceList := make([]string, len(sources))
		for i, src := range sources {
			sourceList[i] = src.Path
		}
		return out.JSON(map[string]interface{}{
			"path":         outputPath,
			"stream":       stream,
			"source_packs": sourceList,
			"merged_by":    mergeMergedBy,
		})
	}

	out.Success("Merged %d packs into %s", len(sources), outputPath)
	out.Print("  Stream: %s\n", stream)
	if mergeIncludeAttestations {
		out.Print("  Attestations: embedded from source packs\n")
	}
	out.Print("  Use 'epack inspect %s' to view contents\n", outputPath)
	out.Print("  Use 'epack sign %s' to sign the merged pack\n", outputPath)
	return nil
}
