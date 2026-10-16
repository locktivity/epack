//go:build !components

package cmd

import "github.com/spf13/cobra"

// epack-core makes no update check: the check needs the GitHub client,
// which only the full build links.
func startUpdateCheck(*cobra.Command) {}

func finishUpdateCheck() {}
