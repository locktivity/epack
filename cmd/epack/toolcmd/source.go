//go:build components

package toolcmd

import (
	"encoding/json"
	"fmt"

	"github.com/locktivity/epack/internal/tool"
	"github.com/spf13/cobra"
)

func newSourceCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "source <tool-name>",
		Short: "Show where a tool was resolved from",
		Long: `Show where a tool was resolved from.

Displays the registry, source descriptor, and signing information
from the lockfile for a configured tool.

Examples:
  epack tool source ai        # Show source for epack-tool-ai
  epack tool source policy    # Show source for epack-tool-policy
  epack tool source ai --json # Output as JSON`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSource(cmd, args[0], jsonOutput)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	return cmd
}

// ToolSource contains source/provenance information about a tool.
type ToolSource struct {
	Name         string              `json:"name"`
	Source       string              `json:"source,omitempty"`
	Version      string              `json:"version,omitempty"`
	ResolvedFrom *ResolvedFromOutput `json:"resolved_from,omitempty"`
	Signing      *SigningOutput      `json:"signing,omitempty"`
	Verification *VerificationOutput `json:"verification,omitempty"`
	Error        string              `json:"error,omitempty"`
}

// ResolvedFromOutput contains resolution provenance.
type ResolvedFromOutput struct {
	Registry   string `json:"registry,omitempty"`
	Descriptor string `json:"descriptor,omitempty"`
}

// SigningOutput contains signing identity information.
type SigningOutput struct {
	Issuer              string `json:"issuer,omitempty"`
	Subject             string `json:"subject,omitempty"`
	SourceRepositoryURI string `json:"source_repository_uri,omitempty"`
	SourceRepositoryRef string `json:"source_repository_ref,omitempty"`
}

// VerificationOutput contains verification status.
type VerificationOutput struct {
	Status     string `json:"status,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
}

func runSource(cmd *cobra.Command, toolName string, jsonOutput bool) error {
	// Get provenance from internal/tool service layer
	prov, err := tool.GetToolProvenance(toolName, "")
	if err != nil {
		// For JSON output, return structured error
		if jsonOutput {
			source := ToolSource{
				Name:  toolName,
				Error: err.Error(),
			}
			return outputSourceJSON(cmd, &source)
		}
		return fmt.Errorf("tool %q: %w", toolName, err)
	}

	// Convert service layer type to CLI output type
	source := ToolSource{
		Name:    prov.Name,
		Source:  prov.Source,
		Version: prov.Version,
	}

	if prov.ResolvedFrom != nil {
		source.ResolvedFrom = &ResolvedFromOutput{
			Registry:   prov.ResolvedFrom.Registry,
			Descriptor: prov.ResolvedFrom.Descriptor,
		}
	}

	if prov.Signing != nil {
		source.Signing = &SigningOutput{
			Issuer:              prov.Signing.Issuer,
			Subject:             prov.Signing.Subject,
			SourceRepositoryURI: prov.Signing.SourceRepositoryURI,
			SourceRepositoryRef: prov.Signing.SourceRepositoryRef,
		}
	}

	if prov.Verification != nil {
		source.Verification = &VerificationOutput{
			Status:     prov.Verification.Status,
			VerifiedAt: prov.Verification.VerifiedAt,
		}
	}

	if jsonOutput {
		return outputSourceJSON(cmd, &source)
	}
	return outputSourceTable(cmd, &source)
}

func outputSourceJSON(cmd *cobra.Command, source *ToolSource) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(source)
}

func outputSourceTable(cmd *cobra.Command, source *ToolSource) error {
	out := cmd.OutOrStdout()

	_, _ = fmt.Fprintf(out, "Tool: %s\n", source.Name)
	_, _ = fmt.Fprintln(out)

	if source.Error != "" {
		_, _ = fmt.Fprintf(out, "Error: %s\n", source.Error)
		return nil
	}

	if source.Source != "" {
		_, _ = fmt.Fprintf(out, "Source:  %s\n", source.Source)
	}
	if source.Version != "" {
		_, _ = fmt.Fprintf(out, "Version: %s\n", source.Version)
	}

	if source.ResolvedFrom != nil {
		_, _ = fmt.Fprintln(out, "\nResolved From:")
		if source.ResolvedFrom.Registry != "" {
			_, _ = fmt.Fprintf(out, "  Registry:   %s\n", source.ResolvedFrom.Registry)
		}
		if source.ResolvedFrom.Descriptor != "" {
			_, _ = fmt.Fprintf(out, "  Descriptor: %s\n", source.ResolvedFrom.Descriptor)
		}
	}

	if source.Signing != nil {
		_, _ = fmt.Fprintln(out, "\nSigning Identity:")
		if source.Signing.Issuer != "" {
			_, _ = fmt.Fprintf(out, "  Issuer:  %s\n", source.Signing.Issuer)
		}
		if source.Signing.Subject != "" {
			_, _ = fmt.Fprintf(out, "  Subject: %s\n", source.Signing.Subject)
		}
		if source.Signing.SourceRepositoryURI != "" {
			_, _ = fmt.Fprintf(out, "  Repo:    %s\n", source.Signing.SourceRepositoryURI)
		}
		if source.Signing.SourceRepositoryRef != "" {
			_, _ = fmt.Fprintf(out, "  Ref:     %s\n", source.Signing.SourceRepositoryRef)
		}
	}

	if source.Verification != nil {
		_, _ = fmt.Fprintln(out, "\nVerification:")
		if source.Verification.Status != "" {
			_, _ = fmt.Fprintf(out, "  Status:      %s\n", source.Verification.Status)
		}
		if source.Verification.VerifiedAt != "" {
			_, _ = fmt.Fprintf(out, "  Verified At: %s\n", source.Verification.VerifiedAt)
		}
	}

	return nil
}
