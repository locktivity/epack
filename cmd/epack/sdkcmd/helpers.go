//go:build components

package sdkcmd

import (
	"bufio"
	"os"
	"strings"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/spf13/cobra"
)

func getOutput(cmd *cobra.Command) *output.Writer {
	return cmdutil.GetOutput(cmd)
}

// isTrustLocalEnabled checks if sdk.trust_local is enabled in user config.
func isTrustLocalEnabled() bool {
	// Check environment variable first
	if os.Getenv("EPACK_SDK_TRUST_LOCAL") == "1" ||
		os.Getenv("EPACK_SDK_TRUST_LOCAL") == "true" ||
		os.Getenv("EPACK_COMPONENT_TRUST_LOCAL") == "1" ||
		os.Getenv("EPACK_COMPONENT_TRUST_LOCAL") == "true" {
		return true
	}

	// Check config file
	cfg, err := userconfig.LoadConfig()
	if err != nil {
		return false
	}

	return cfg.Component.TrustLocal
}

// promptConfirm asks for y/N confirmation.
func promptConfirm(out *output.Writer, prompt string) bool {
	out.Print("%s", prompt)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}
