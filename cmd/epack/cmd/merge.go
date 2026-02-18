package cmd

import (
	"os"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/cli/sigstore"
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
	outputPath := args[0]
	sourcePaths := args[1:]
	out := outputWriter()
	ctx := cmdContext(cmd)

	// Interactive prompt for stream if not provided
	stream := mergeStream
	if stream == "" {
		if out.IsTTY() && !out.IsJSON() {
			s, err := out.PromptRequired("Stream identifier (e.g., myorg/merged): ")
			if err != nil {
				return exitError("--stream is required")
			}
			stream = s
		} else {
			return exitError("--stream is required")
		}
	}

	// Check if output exists
	if !mergeForce && !mergeDryRun {
		if _, err := os.Stat(outputPath); err == nil {
			return exitError("output file %q already exists (use --force to overwrite)", outputPath)
		}
	}

	// Build source pack list
	var sources []merge.SourcePack
	for _, path := range sourcePaths {
		// Check source exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return exitError("source pack not found: %s", path)
		}
		sources = append(sources, merge.SourcePack{Path: path})
	}

	if len(sources) == 0 {
		return exitError("at least one source pack is required")
	}

	// Dry-run mode: show what would be merged without creating a pack
	if mergeDryRun {
		return runMergeDryRun(sources, outputPath, out)
	}

	out.Verbose("Merging %d packs into %s\n", len(sources), outputPath)

	// Perform merge
	opts := merge.Options{
		Stream:              stream,
		MergedBy:            mergeMergedBy,
		IncludeAttestations: mergeIncludeAttestations,
		VerifyAttestations:  mergeIncludeAttestations && !mergeInsecureSkipAttestationVerify,
	}

	// Create verifier if verification is enabled
	if opts.VerifyAttestations {
		// SECURITY: Require explicit identity policy or explicit opt-out.
		// Without this, an attacker could sign malicious attestations with
		// any valid Sigstore identity and have them embedded in merged packs.
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
	}

	if err := merge.Merge(ctx, sources, outputPath, opts); err != nil {
		return exitError("failed to merge packs: %v", err)
	}

	// Output result
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

// packSummary contains summary information about a pack for dry-run output
type packSummary struct {
	Path         string
	Stream       string
	Artifacts    int
	TotalSize    int64
	Attestations int
}

func runMergeDryRun(sources []merge.SourcePack, outputPath string, out *output.Writer) error {
	var summaries []packSummary
	var totalArtifacts int
	var totalSize int64
	var totalAttestations int

	for _, src := range sources {
		p, err := pack.Open(src.Path)
		if err != nil {
			return exitError("failed to open pack %s: %v", src.Path, err)
		}

		manifest := p.Manifest()
		var packSize int64
		artifactCount := 0
		for _, artifact := range manifest.Artifacts {
			if artifact.Type == "embedded" {
				artifactCount++
				if artifact.Size != nil {
					size, _ := artifact.Size.Int64()
					packSize += size
				}
			}
		}

		attestationCount := len(p.ListAttestations())
		_ = p.Close() // Error intentionally ignored in dry-run preview

		summaries = append(summaries, packSummary{
			Path:         src.Path,
			Stream:       manifest.Stream,
			Artifacts:    artifactCount,
			TotalSize:    packSize,
			Attestations: attestationCount,
		})

		totalArtifacts += artifactCount
		totalSize += packSize
		totalAttestations += attestationCount
	}

	// Output result
	if out.IsJSON() {
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
			"total_artifacts":      totalArtifacts,
			"total_size":           totalSize,
			"total_attestations":   totalAttestations,
			"include_attestations": mergeIncludeAttestations,
		})
	}

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
		if s.Attestations > 0 {
			if mergeIncludeAttestations {
				out.Print("    Attestations: %d (will be embedded)\n", s.Attestations)
			} else {
				out.Print("    Attestations: %d (will NOT be embedded, use --include-attestations)\n", s.Attestations)
			}
		}
	}

	out.Print("\n")
	out.Print("%s\n", palette.Bold("Result:"))
	out.Print("  Total artifacts: %d\n", totalArtifacts)
	out.Print("  Total size: %s\n", output.FormatBytes(totalSize))
	if mergeIncludeAttestations {
		out.Print("  Attestations: %d (will be embedded)\n", totalAttestations)
	}

	return nil
}
