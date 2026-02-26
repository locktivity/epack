package push

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/netpolicy"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/progress"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/pack"
)

// StepCallback is called when a push step starts or completes.
// step is the step name, started indicates whether the step is starting (true) or done (false).
type StepCallback func(step string, started bool)

// UploadProgressCallback is called periodically during upload with bytes written and total.
type UploadProgressCallback func(written, total int64)

// Options configures a push operation.
type Options struct {
	// Remote is the name of the remote to push to (required).
	Remote string

	// PackPath is the path to the pack file (required).
	PackPath string

	// Environment is the environment override (optional).
	// Applies configuration from environments.<env> section.
	Environment string

	// Workspace overrides the target workspace (optional).
	Workspace string

	// Labels are release labels to apply (optional).
	Labels []string

	// Notes are release notes (optional).
	Notes string

	// RunsPaths are additional paths to search for run results (optional).
	RunsPaths []string

	// NoRuns disables automatic run syncing.
	NoRuns bool

	// NonInteractive disables interactive prompts.
	NonInteractive bool

	// Frozen requires all adapters to be pinned with digests (CI mode).
	// SECURITY: When true, adapters must be verified against lockfile digests.
	Frozen bool

	// InsecureAllowUnpinned allows execution of adapters not pinned in lockfile.
	// SECURITY WARNING: This bypasses digest verification for source-based adapters.
	InsecureAllowUnpinned bool

	// Stderr is where adapter stderr output is written.
	// If nil, os.Stderr is used.
	Stderr io.Writer

	// OnStep is called when each step of the push workflow starts/completes.
	// Optional; if nil, no callbacks are made.
	OnStep StepCallback

	// OnUploadProgress is called periodically during upload.
	// Optional; if nil, no progress is reported.
	OnUploadProgress UploadProgressCallback

	// PromptInstallAdapter is called when the adapter is not installed.
	// If it returns true, the adapter will be installed automatically.
	// If nil, no prompt is shown and an error is returned instead.
	PromptInstallAdapter func(remoteName, adapterName string) bool
}

// Result contains the result of a push operation.
type Result struct {
	// Release contains the release information from the remote.
	Release *remote.ReleaseResult

	// Links contains URLs returned by the remote.
	Links map[string]string

	// SyncedRuns lists run IDs that were successfully synced.
	SyncedRuns []string

	// FailedRuns lists run IDs that failed to sync.
	FailedRuns []string

	// ReceiptPath is the path to the written receipt file.
	ReceiptPath string
}

// Push uploads a pack to a remote registry.
//
// SECURITY: This function performs TOCTOU-safe execution for source-based adapters.
// The adapter binary is verified against the lockfile digest before execution,
// preventing attacks where an attacker modifies the binary between resolution
// and execution.
func Push(ctx context.Context, opts Options) (*Result, error) {
	if opts.Remote == "" {
		return nil, fmt.Errorf("remote is required")
	}
	if opts.PackPath == "" {
		return nil, fmt.Errorf("pack path is required")
	}

	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Helper to emit step callbacks
	step := func(name string, started bool) {
		if opts.OnStep != nil {
			opts.OnStep(name, started)
		}
	}

	// Step 1: Load and verify pack
	step("Verifying pack integrity", true)
	absPackPath, err := filepath.Abs(opts.PackPath)
	if err != nil {
		return nil, fmt.Errorf("resolving pack path: %w", err)
	}

	p, err := pack.Open(absPackPath)
	if err != nil {
		return nil, fmt.Errorf("opening pack: %w", err)
	}
	defer func() { _ = p.Close() }()

	if err := p.VerifyIntegrity(); err != nil {
		return nil, fmt.Errorf("pack verification failed: %w", err)
	}
	step("Verifying pack integrity", false)

	packInfo, err := os.Stat(absPackPath)
	if err != nil {
		return nil, fmt.Errorf("getting pack info: %w", err)
	}

	packDigest := p.Manifest().PackDigest
	packSize := packInfo.Size()

	// Step 2: Load remote configuration
	step("Loading remote configuration", true)
	projectRoot, err := project.FindRoot("")
	if err != nil {
		return nil, fmt.Errorf("finding project root: %w", err)
	}

	configPath := filepath.Join(projectRoot, "epack.yaml")
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	remoteCfg, err := remote.ResolveRemoteConfig(cfg, opts.Remote, opts.Environment)
	if err != nil {
		return nil, err
	}
	step("Loading remote configuration", false)

	// Step 3: Resolve adapter binary path (with auto-install if needed)
	step("Resolving adapter", true)

	// Wrap step callback for remote package
	remoteStep := remote.StepCallback(step)

	exec, caps, err := remote.PrepareAdapterExecutor(
		ctx, projectRoot, opts.Remote, cfg, remoteCfg,
		remote.AdapterExecutorOptions{
			PromptInstall: opts.PromptInstallAdapter,
			Step:          remoteStep,
			Stderr:        stderr,
			Verification: remote.VerificationOptions{
				Frozen:                opts.Frozen,
				AllowUnverifiedSource: opts.InsecureAllowUnpinned,
			},
		})
	if err != nil {
		return nil, err
	}
	defer exec.Close()

	if !caps.SupportsPrepareFinalize() {
		return nil, fmt.Errorf("adapter does not support prepare/finalize upload protocol")
	}
	step("Resolving adapter", false)

	// Step 4: Build target config with overrides
	target := remote.TargetConfig{
		Workspace:   remoteCfg.Target.Workspace,
		Environment: remoteCfg.Target.Environment,
	}
	if opts.Workspace != "" {
		target.Workspace = opts.Workspace
	}

	// Merge labels from config and options
	labels := append([]string{}, remoteCfg.Release.Labels...)
	labels = append(labels, opts.Labels...)

	// Build release info
	releaseInfo := remote.ReleaseInfo{
		Labels: labels,
		Notes:  opts.Notes,
	}
	if releaseInfo.Notes == "" {
		releaseInfo.Notes = remoteCfg.Release.Notes
	}

	// Add source info from environment variables
	if remoteCfg.Release.Source != nil {
		releaseInfo.Source = buildSourceInfo(remoteCfg.Release.Source)
	}

	// Step 5: Execute push workflow
	step("Preparing upload", true)

	// Call push.prepare
	prepReq := &remote.PrepareRequest{
		Remote: opts.Remote,
		Target: target,
		Pack: remote.PackInfo{
			Path:      absPackPath,
			Digest:    packDigest,
			SizeBytes: packSize,
		},
		Release: releaseInfo,
	}

	prepResp, err := exec.Prepare(ctx, prepReq)
	if err != nil {
		return nil, fmt.Errorf("push.prepare failed: %w", err)
	}
	step("Preparing upload", false)

	// Step 6: Perform HTTP upload (skip if method is "skip" - pack already exists)
	if prepResp.Upload.Method != "skip" {
		step("Uploading pack", true)
		if err := uploadPackWithProgress(ctx, absPackPath, prepResp.Upload, remoteCfg.Transport, opts.OnUploadProgress); err != nil {
			return nil, fmt.Errorf("upload failed: %w", err)
		}
		step("Uploading pack", false)
	}

	// Step 7: Call push.finalize
	step("Finalizing release", true)
	finalReq := &remote.FinalizeRequest{
		Remote: opts.Remote,
		Target: target,
		Pack: remote.PackInfo{
			Path:      absPackPath,
			Digest:    packDigest,
			SizeBytes: packSize,
		},
		FinalizeToken: prepResp.FinalizeToken,
	}

	finalResp, err := exec.Finalize(ctx, finalReq)
	if err != nil {
		return nil, fmt.Errorf("push.finalize failed: %w", err)
	}
	step("Finalizing release", false)

	result := &Result{
		Release: &finalResp.Release,
		Links:   finalResp.Links,
	}

	// Step 8: Sync runs (unless disabled)
	if !opts.NoRuns && remoteCfg.Runs.SyncEnabled() && caps.SupportsRunsSync() {
		step("Syncing runs", true)
		syncedRuns, failedRuns, syncErr := syncRuns(ctx, exec, target, packDigest, absPackPath, remoteCfg, opts.RunsPaths)
		result.SyncedRuns = syncedRuns
		result.FailedRuns = failedRuns
		step("Syncing runs", false)
		if syncErr != nil && remoteCfg.Runs.RequireSuccess {
			return result, fmt.Errorf("run sync failed (require_success=true): %w", syncErr)
		}
	}

	// Step 9: Write receipt
	receipt := NewReceipt(
		opts.Remote,
		target,
		absPackPath,
		packDigest,
		packSize,
		&finalResp.Release,
		finalResp.Links,
		result.SyncedRuns,
		result.FailedRuns,
	)

	writer := &ReceiptWriter{
		BaseDir: filepath.Join(packpath.SidecarDir(absPackPath), "receipts", "push"),
	}
	receiptPath, err := writer.Write(receipt)
	if err != nil {
		// Log but don't fail - receipt is for audit, not critical path
		_, _ = fmt.Fprintf(stderr, "Warning: failed to write receipt: %v\n", err)
	}
	result.ReceiptPath = receiptPath

	return result, nil
}

// buildSourceInfo builds source info from environment variables.
func buildSourceInfo(src *config.RemoteReleaseSource) *remote.SourceInfo {
	info := &remote.SourceInfo{}

	if src.Git != nil {
		if src.Git.SHAEnv != "" {
			info.GitSHA = os.Getenv(src.Git.SHAEnv)
		}
	}
	if src.CI != nil {
		if src.CI.RunURLEnv != "" {
			info.CIRunURL = os.Getenv(src.CI.RunURLEnv)
		}
	}

	if info.GitSHA == "" && info.CIRunURL == "" {
		return nil
	}
	return info
}

// uploadPackWithProgress uploads the pack file using the provided upload info,
// optionally reporting progress via a callback.
//
// SECURITY: This function validates URLs from untrusted adapter responses to prevent SSRF.
// Only HTTPS URLs are allowed. HTTP to localhost requires explicit opt-in via transport config.
// File URLs are allowed for local filesystem remotes, optionally confined to a root directory.
func uploadPackWithProgress(ctx context.Context, packPath string, upload remote.UploadInfo, transport config.RemoteTransport, onProgress UploadProgressCallback) error {
	// Check for file:// URL (local filesystem remote)
	parsed, err := url.Parse(upload.URL)
	if err != nil {
		return fmt.Errorf("invalid upload URL: %w", err)
	}

	if parsed.Scheme == "file" {
		return uploadPackToFile(ctx, packPath, parsed.Path, transport.FileRoot, onProgress)
	}

	// SECURITY: Validate URL from untrusted adapter response to prevent SSRF.
	// Adapters can return arbitrary URLs; we must validate before uploading.
	if err := validateAdapterURL(upload.URL, transport.AllowLoopbackHTTP); err != nil {
		return fmt.Errorf("invalid upload URL from adapter: %w", err)
	}

	f, err := os.Open(packPath)
	if err != nil {
		return fmt.Errorf("opening pack: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("getting pack size: %w", err)
	}

	// Wrap file in progress reader if callback provided
	var body io.Reader = f
	if onProgress != nil {
		body = progress.NewReader(f, info.Size(), progress.Callback(onProgress))
	}

	req, err := http.NewRequestWithContext(ctx, upload.Method, upload.URL, body)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.ContentLength = info.Size()
	for k, v := range upload.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Transport: netpolicy.SecureTransport(),
		Timeout:   30 * time.Minute, // Large file upload timeout
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// uploadPackToFile handles file:// URLs by copying the pack to the local path.
//
// SECURITY: Uses safefile operations with symlink protection to prevent attacks.
// Requires fileRoot to be set - file:// URLs are rejected without explicit confinement.
func uploadPackToFile(ctx context.Context, packPath, destPath string, fileRoot string, onProgress UploadProgressCallback) error {
	// SECURITY: Require file_root for file:// URLs.
	// This forces users to explicitly configure where file operations are allowed,
	// preventing adapters from directing writes to arbitrary locations.
	if fileRoot == "" {
		return fmt.Errorf("file:// URLs require transport.file_root to be configured in the remote")
	}

	if err := validateFileRoot(destPath, fileRoot); err != nil {
		return err
	}

	src, err := os.Open(packPath)
	if err != nil {
		return fmt.Errorf("opening pack: %w", err)
	}
	defer func() { _ = src.Close() }()

	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("getting pack size: %w", err)
	}

	// SECURITY: Use safefile.MkdirAll which uses O_NOFOLLOW at each path component
	// to prevent symlink attacks when creating parent directories.
	destDir := filepath.Dir(destPath)
	if err := safefile.MkdirAll(fileRoot, destDir); err != nil {
		return fmt.Errorf("creating destination directory: %w", err)
	}

	// SECURITY: Use safefile.OpenForWrite which uses O_NOFOLLOW to atomically refuse symlinks.
	// This prevents TOCTOU attacks where an attacker places a symlink at the destination.
	dst, err := safefile.OpenForWrite(destPath)
	if err != nil {
		return fmt.Errorf("creating destination file: %w", err)
	}
	defer func() { _ = dst.Close() }()

	// Copy with progress if callback provided
	var reader io.Reader = src
	if onProgress != nil {
		reader = progress.NewReader(src, info.Size(), progress.Callback(onProgress))
	}

	if _, err := io.Copy(dst, reader); err != nil {
		return fmt.Errorf("copying pack: %w", err)
	}

	return nil
}

// syncRuns syncs run results to the remote.
func syncRuns(
	ctx context.Context,
	exec *remote.Executor,
	target remote.TargetConfig,
	packDigest string,
	packPath string,
	cfg *config.RemoteConfig,
	extraPaths []string,
) (synced []string, failed []string, err error) {
	// Find run result files
	runs, err := findRuns(packPath, cfg, extraPaths)
	if err != nil {
		return nil, nil, fmt.Errorf("finding runs: %w", err)
	}

	if len(runs) == 0 {
		return nil, nil, nil
	}

	// Sync runs
	req := &remote.RunsSyncRequest{
		Target:     target,
		PackDigest: packDigest,
		Runs:       runs,
	}

	resp, err := exec.SyncRuns(ctx, req)
	if err != nil {
		// Return all as failed
		for _, run := range runs {
			failed = append(failed, run.RunID)
		}
		return nil, failed, err
	}

	for _, item := range resp.Items {
		if item.Status == "accepted" || item.Status == "duplicate" {
			synced = append(synced, item.RunID)
		} else {
			failed = append(failed, item.RunID)
		}
	}

	return synced, failed, nil
}

// findRuns finds run result files for syncing.
func findRuns(packPath string, cfg *config.RemoteConfig, extraPaths []string) ([]remote.RunInfo, error) {
	// Default paths
	paths := cfg.Runs.Paths
	if len(paths) == 0 {
		paths = []string{".epack/runs/**/result.json"}
	}
	paths = append(paths, extraPaths...)

	// Base directory is pack sidecar
	baseDir := packpath.SidecarDir(packPath)

	var runs []remote.RunInfo
	seen := make(map[string]bool)

	for _, pattern := range paths {
		// If pattern is relative, make it relative to pack sidecar
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(baseDir, pattern)
		}

		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue // Invalid pattern, skip
		}

		for _, match := range matches {
			if seen[match] {
				continue
			}
			seen[match] = true

			// Extract run ID from path
			// Expected: .../runs/<toolname>/<runid>/result.json
			dir := filepath.Dir(match)
			runID := filepath.Base(dir)
			if runID == "" || runID == "." {
				continue
			}

			// Read file to compute digest
			data, err := os.ReadFile(match)
			if err != nil {
				continue
			}

			// Compute SHA256 digest
			digest := computeSHA256(data)

			runs = append(runs, remote.RunInfo{
				RunID:        runID,
				ResultPath:   match,
				ResultDigest: digest,
			})
		}
	}

	return runs, nil
}

// computeSHA256 computes SHA256 digest of data.
func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h)
}

// validateAdapterURL validates a URL provided by an untrusted remote adapter.
//
// SECURITY: Remote adapters can return arbitrary URLs for download/upload operations.
// Prevents SSRF attacks by enforcing:
//   - HTTPS scheme required
//   - HTTP to localhost requires explicit allowLoopbackHTTP opt-in
//   - Valid URL structure
//
// Note: We intentionally do NOT enforce a host allowlist here because adapters
// legitimately need to return URLs to various cloud storage providers (S3, GCS, Azure, etc.).
// The pack digest verification provides integrity protection after download.
func validateAdapterURL(rawURL string, allowLoopbackHTTP bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}

	hostname := parsed.Hostname()
	isLoopback := netpolicy.IsLoopback(hostname)

	// SECURITY: Require HTTPS for all non-loopback URLs.
	// This prevents:
	// - Credential sniffing on the network
	// - MITM attacks injecting malicious content
	// - Downgrade attacks
	switch parsed.Scheme {
	case "https":
		// Always allowed
		return nil
	case "http":
		// SECURITY: HTTP to localhost requires explicit opt-in via transport config.
		// Even localhost HTTP can be dangerous (malicious local services, SSRF to internal APIs).
		if isLoopback && allowLoopbackHTTP {
			return nil
		}
		if isLoopback {
			return fmt.Errorf("HTTP to localhost requires allow_loopback_http: true in remote transport config")
		}
		return fmt.Errorf("HTTP scheme not allowed for non-localhost URL %q; HTTPS required", hostname)
	default:
		return fmt.Errorf("scheme %q not allowed; must be https", parsed.Scheme)
	}
}

// validateFileRoot validates that filePath is contained within the specified root directory.
//
// SECURITY: This is a string-based pre-check before file operations. The actual file
// operations use O_NOFOLLOW to provide TOCTOU-safe symlink rejection. This pre-check
// adds defense-in-depth by rejecting obvious traversal attempts early.
func validateFileRoot(filePath, fileRoot string) error {
	// Get absolute paths for comparison
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("resolving file path: %w", err)
	}

	absRoot, err := filepath.Abs(fileRoot)
	if err != nil {
		return fmt.Errorf("resolving file root: %w", err)
	}

	// Ensure root ends with separator for prefix comparison
	rootWithSep := absRoot
	if !strings.HasSuffix(rootWithSep, string(filepath.Separator)) {
		rootWithSep += string(filepath.Separator)
	}

	// Check containment
	if !strings.HasPrefix(absPath, rootWithSep) && absPath != absRoot {
		return errors.E(errors.PathTraversal,
			fmt.Sprintf("file path %q escapes configured file_root %q", filePath, fileRoot), nil)
	}

	return nil
}
