//go:build components

package contextcmd

import (
	"encoding/json"

	"github.com/locktivity/epack/internal/buildcontext"
	"github.com/spf13/cobra"
)

func newBuildCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "build",
		Short: "Print runtime build context as JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			payload := map[string]any{}
			if ctx := buildcontext.Build(nil); ctx != nil {
				if mapped := ctx.ToMap(); mapped != nil {
					payload = mapped
				}
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(payload)
		},
	}
}
