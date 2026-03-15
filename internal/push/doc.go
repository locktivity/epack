// Package push implements the push workflow for uploading packs to remote registries.
//
// The push workflow uses the Remote Adapter Protocol to communicate with registry backends.
// Remote adapters are external binaries (epack-remote-<name>) that handle authentication
// and upload operations. See the internal/remote package for protocol details.
//
// # Workflow
//
// The push workflow consists of:
//  1. Load and verify the pack locally
//  2. Load remote configuration from epack.yaml
//  3. Discover and validate the adapter binary
//  4. Call push.prepare to get a presigned upload URL
//  5. Perform HTTP upload to the provided URL
//  6. Call push.finalize to create the release
//  7. Sync run ledgers (unless disabled)
//  8. Write a receipt file for audit trail
//
// # Usage
//
//	result, err := push.Push(ctx, push.Options{
//	    Remote:   "locktivity",
//	    PackPath: "packs/acme-prod.epack",
//	    Labels:   []string{"monthly", "soc2"},
//	})
//
// # Receipt Files
//
// Push operations write receipt files to the project-local
// .epack/receipts/push/<remote>/<timestamp>_<digest>.json path.
// These provide an audit trail of all push operations and include release information,
// synced runs, and client metadata.
//
// # Security
//
// Remote adapters are verified against the lockfile when using source-based configuration.
// PATH-only adapters are unverified and should be used with caution.
// Authentication credentials are managed by the adapter, not this package.
package push
