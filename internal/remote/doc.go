// Package remote implements the Remote Adapter Protocol for epack push/pull operations.
//
// Remote adapters are external binaries that handle communication with remote registries.
// They follow a JSON-over-stdin/stdout protocol, similar to how Git credential helpers work.
//
// # Adapter Naming
//
// Adapters are named epack-remote-<name>, for example:
//   - epack-remote-locktivity
//   - epack-remote-s3
//   - epack-remote-filesystem
//
// # Discovery
//
// Adapters are discovered from multiple locations:
//  1. Project lockfile: Source-based remotes are installed to .epack/remotes/<name>/<version>/
//  2. External binary: Configured via binary: field in epack.yaml
//  3. System PATH: For adapter-only remotes (adapter: field without source/binary)
//
// # Protocol
//
// The protocol uses newline-delimited JSON. Requests are sent on stdin,
// responses on stdout. Stderr is used for human-readable log messages.
//
// Commands:
//   - --capabilities: Returns adapter capabilities (synchronous, no stdin)
//   - push.prepare: Get presigned upload URL
//   - push.finalize: Finalize upload and create release
//   - runs.sync: Sync run ledgers to remote (optional)
//   - auth.login: Authenticate with remote (optional)
//   - auth.whoami: Query current identity (optional)
//
// # Security
//
// Adapters are external binaries and should be treated with appropriate caution:
//   - Source-based adapters are verified via Sigstore and lockfile digests (epack.lock.yaml)
//   - External binary adapters have their digest pinned in the lockfile
//   - PATH-only adapters are unverified and should be used with caution
//   - Authentication is managed by the adapter, not epack
//
// # Example Usage
//
//	// Find and probe adapter capabilities
//	adapter := remote.FindAdapter(ctx, "locktivity", remote.DiscoverOptions{
//	    ProbeManaged: true,
//	})
//	if adapter == nil {
//	    // Adapter not installed
//	}
//
//	// Execute push workflow
//	exec := remote.NewExecutor(adapter.BinaryPath, adapter.Name)
//	prepResp, err := exec.Prepare(ctx, &remote.PrepareRequest{
//	    Remote: "locktivity",
//	    Target: remote.TargetConfig{Workspace: "acme", Environment: "prod"},
//	    Pack:   remote.PackInfo{Path: "pack.epack", Digest: "sha256:...", SizeBytes: 1234},
//	})
//	// Upload to prepResp.Upload.URL
//	// Then call exec.Finalize(...)
package remote
