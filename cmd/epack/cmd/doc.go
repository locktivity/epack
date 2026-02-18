// Package cmd implements the epack command-line interface.
//
// Commands:
//
//	epack build      Create an evidence pack from artifacts
//	epack sign       Sign a pack with Sigstore
//	epack verify     Verify pack integrity and attestations
//	epack inspect    Display pack contents
//	epack list       List artifacts, attestations, or sources
//	epack extract    Extract artifacts from a pack
//	epack merge      Combine multiple packs
//	epack diff       Compare two packs
//	epack version    Show version information
//	epack completion Generate shell completions
//
// Global flags:
//
//	-q, --quiet      Suppress non-essential output
//	--json           Output in JSON format
//	--no-color       Disable colored output
//	-v, --verbose    Verbose output
//
// See 'epack --help' or 'epack <command> --help' for details.
package cmd
