package cmd

import (
	"runtime"

	"github.com/locktivity/epack/internal/version"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

// buildVariant returns a description of enabled features based on build tags.
func buildVariant() string {
	if ComponentsEnabled {
		return "full"
	}
	return "core"
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display epack version, commit, and build information.`,
	Run: func(cmd *cobra.Command, args []string) {
		out := outputWriter()

		if out.IsJSON() {
			_ = out.JSON(map[string]interface{}{
				"version":            version.Version,
				"commit":             version.Commit,
				"build_date":         version.BuildDate,
				"go_version":         runtime.Version(),
				"os":                 runtime.GOOS,
				"arch":               runtime.GOARCH,
				"components_enabled": ComponentsEnabled,
			})
			return
		}

		out.Print("epack version %s (%s)\n", version.Version, buildVariant())
		if out.IsVerbose() {
			out.Print("  Commit:     %s\n", version.Commit)
			out.Print("  Built:      %s\n", version.BuildDate)
			out.Print("  Go version: %s\n", runtime.Version())
			out.Print("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
			out.Print("  Features:   %s\n", buildVariant())
		}
	},
}
