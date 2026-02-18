//go:build components

package utilitycmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/locktivity/epack/internal/userconfig"
	"github.com/spf13/cobra"
)

func newListCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List installed utilities",
		Long: `List all utilities installed in ~/.epack/bin/.

EXAMPLES

  # List installed utilities
  epack utility list

  # JSON output
  epack utility list --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			lf, err := userconfig.LoadUtilitiesLock()
			if err != nil {
				return fmt.Errorf("loading utilities lock: %w", err)
			}

			if len(lf.Utilities) == 0 {
				fmt.Println("No utilities installed.")
				fmt.Println("")
				fmt.Println("Install with: epack utility install <name> <source>")
				return nil
			}

			// Sort utility names
			names := make([]string, 0, len(lf.Utilities))
			for name := range lf.Utilities {
				names = append(names, name)
			}
			sort.Strings(names)

			if jsonOutput {
				return printUtilitiesJSON(lf, names)
			}

			// Table output
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "NAME\tVERSION\tSOURCE\tVERIFIED")

			for _, name := range names {
				util := lf.Utilities[name]
				verified := "no"
				if util.Verification != nil && util.Verification.Status == "verified" {
					verified = "yes"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, util.Version, util.Source, verified)
			}

			return w.Flush()
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")

	return cmd
}

func printUtilitiesJSON(lf *userconfig.UtilitiesLock, names []string) error {
	// For now, just print a simple JSON format
	fmt.Println("{")
	fmt.Println("  \"utilities\": [")
	for i, name := range names {
		util := lf.Utilities[name]
		verified := util.Verification != nil && util.Verification.Status == "verified"
		comma := ","
		if i == len(names)-1 {
			comma = ""
		}
		fmt.Printf("    {\"name\": %q, \"version\": %q, \"source\": %q, \"verified\": %v}%s\n",
			name, util.Version, util.Source, verified, comma)
	}
	fmt.Println("  ]")
	fmt.Println("}")
	return nil
}
