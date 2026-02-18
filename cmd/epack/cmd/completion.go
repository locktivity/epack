package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(completionCmd)
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for epack.

To load completions:

Bash:
  $ source <(epack completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ epack completion bash > /etc/bash_completion.d/epack
  # macOS:
  $ epack completion bash > $(brew --prefix)/etc/bash_completion.d/epack

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. Execute once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ epack completion zsh > "${fpath[1]}/_epack"

  # You will need to start a new shell for this setup to take effect.

Fish:
  $ epack completion fish | source
  # To load completions for each session, execute once:
  $ epack completion fish > ~/.config/fish/completions/epack.fish

PowerShell:
  PS> epack completion powershell | Out-String | Invoke-Expression
  # To load completions for every new session, run:
  PS> epack completion powershell > epack.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		out := cmd.OutOrStdout()
		switch args[0] {
		case "bash":
			_ = cmd.Root().GenBashCompletion(out)
		case "zsh":
			_ = cmd.Root().GenZshCompletion(out)
		case "fish":
			_ = cmd.Root().GenFishCompletion(out, true)
		case "powershell":
			_ = cmd.Root().GenPowerShellCompletionWithDesc(out)
		}
	},
}
