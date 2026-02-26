package pull

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
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/netpolicy"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/progress"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/pack"
)

// StepCallback is called when a pull step starts or completes.
// step is the step name, started indicates whether the step is starting (true) or done (false).
type StepCallback func(step string, started bool)

// DownloadProgressCallback is called periodically during download with bytes read and total.
type DownloadProgressCallback func(read, total int64)

// Options configures a pull operation.
type Options struct {
	// Remote is the name of the remote to pull from (required).
	Remote string

	// Ref specifies which pack to pull (required).
	// Exactly one of Digest, ReleaseID, Version, or Latest should be set.
	Ref remote.PackRef

	// OutputPath is the destination path for the downloaded pack.
	// If empty, defaults to ./<stream>.pack
	OutputPath string

	// Force allows overwriting an existing file.
	Force bool

	// Environment is the environment override (optional).
	// Applies configuration from environments.<env> section.
	Environment string

	// Workspace overrides the target workspace (optional).
	Workspace string

	// Verify enables pack integrity verification after download.
	Verify bool

	// Frozen requires all adapters to be pinned with digests (CI mode).
	// SECURITY: When true, adapters must be verified against lockfile digests.
	Frozen bool

	// InsecureAllowUnpinned allows execution of adapters not pinned in lockfile.
	// SECURITY WARNING: This bypasses digest verification for source-based adapters.
	InsecureAllowUnpinned bool

	// Stderr is where adapter stderr output is written.
	// If nil, os.Stderr is used.
	Stderr io.Writer

	// OnStep is called when each step of the pull workflow starts/completes.
	// Optional; if nil, no callbacks are made.
	OnStep StepCallback

	// OnDownloadProgress is called periodically during download.
	// Optional; if nil, no progress is reported.
	OnDownloadProgress DownloadProgressCallback

	// PromptInstallAdapter is called when the adapter is not installed.
	// If it returns true, the adapter will be installed automatically.
	// If nil, no prompt is shown and an error is returned instead.
	PromptInstallAdapter func(remoteName, adapterName string) bool
}

// Result contains the result of a pull operation.
type Result struct {
	// OutputPath is the path to the downloaded pack file.
	OutputPath string

	// Pack contains metadata about the pulled pack.
	Pack *remote.PackMetadata

	// Verified indicates whether the pack was verified after download.
	Verified bool

	// ReceiptPath is the path to the written receipt file.
	ReceiptPath string
}

// Pull downloads a pack from a remote registry.
//
// SECURITY: This function performs TOCTOU-safe execution for source-based adapters.
// The adapter binary is verified against the lockfile digest before execution,
// preventing attacks where an attacker modifies the binary between resolution
// and execution.
func Pull(ctx context.Context, opts Options) (*Result, error) {
	if opts.Remote == "" {
		return nil, fmt.Errorf("remote is required")
	}
	if opts.Ref.Digest == "" && !opts.Ref.Latest && opts.Ref.ReleaseID == "" && opts.Ref.Version == "" {
		// None set - default to latest
		opts.Ref.Latest = true
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

	// Step 1: Load remote configuration
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

	// Step 2: Resolve adapter binary path (with auto-install if needed)
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

	if !caps.SupportsPull() {
		return nil, fmt.Errorf("adapter does not support pull operations")
	}
	step("Resolving adapter", false)

	// Step 3: Build target config with overrides
	target := remote.TargetConfig{
		Workspace:   remoteCfg.Target.Workspace,
		Environment: remoteCfg.Target.Environment,
	}
	if opts.Workspace != "" {
		target.Workspace = opts.Workspace
	}

	// Step 4: Execute pull.prepare
	step("Preparing download", true)

	prepReq := &remote.PullPrepareRequest{
		Remote: opts.Remote,
		Target: target,
		Ref:    opts.Ref,
	}

	prepResp, err := exec.PullPrepare(ctx, prepReq)
	if err != nil {
		return nil, fmt.Errorf("pull.prepare failed: %w", err)
	}
	step("Preparing download", false)

	// Determine output path
	outputPath := opts.OutputPath
	if outputPath == "" {
		// Default to <stream>.epack in current directory
		streamName := sanitizeStreamName(prepResp.Pack.Stream)
		outputPath = streamName + packpath.PackExtension
	}

	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return nil, fmt.Errorf("resolving output path: %w", err)
	}

	// Check if output exists
	if !opts.Force {
		if _, err := os.Stat(absOutputPath); err == nil {
			return nil, fmt.Errorf("output file %q already exists (use --force to overwrite)", outputPath)
		}
	}

	// Step 5: Perform HTTP download
	step("Downloading pack", true)
	downloadedDigest, err := downloadPackWithProgress(ctx, absOutputPath, prepResp.Download, prepResp.Pack.SizeBytes, remoteCfg.Transport, opts.OnDownloadProgress)
	if err != nil {
		_ = os.Remove(absOutputPath) // Clean up partial download
		return nil, fmt.Errorf("download failed: %w", err)
	}
	step("Downloading pack", false)

	// Verify digest matches
	if downloadedDigest != prepResp.Pack.Digest {
		_ = os.Remove(absOutputPath)
		return nil, fmt.Errorf("digest mismatch: expected %s, got %s", prepResp.Pack.Digest, downloadedDigest)
	}

	result := &Result{
		OutputPath: absOutputPath,
		Pack:       &prepResp.Pack,
	}

	// Step 6: Verify pack integrity (optional)
	if opts.Verify {
		step("Verifying pack integrity", true)
		p, err := pack.Open(absOutputPath)
		if err != nil {
			_ = os.Remove(absOutputPath)
			return nil, fmt.Errorf("opening pack for verification: %w", err)
		}
		if err := p.VerifyIntegrity(); err != nil {
			_ = p.Close()
			_ = os.Remove(absOutputPath)
			return nil, fmt.Errorf("pack verification failed: %w", err)
		}
		_ = p.Close()
		result.Verified = true
		step("Verifying pack integrity", false)
	}

	// Step 7: Call pull.finalize
	step("Finalizing download", true)
	finalReq := &remote.PullFinalizeRequest{
		Remote:        opts.Remote,
		Target:        target,
		Digest:        prepResp.Pack.Digest,
		FinalizeToken: prepResp.FinalizeToken,
	}

	_, err = exec.PullFinalize(ctx, finalReq)
	if err != nil {
		// Log but don't fail - finalize is for analytics/audit, not critical
		_, _ = fmt.Fprintf(stderr, "Warning: pull.finalize failed: %v\n", err)
	}
	step("Finalizing download", false)

	// Step 8: Write receipt
	receipt := NewReceipt(
		opts.Remote,
		target,
		absOutputPath,
		&prepResp.Pack,
		result.Verified,
	)

	writer := &ReceiptWriter{
		BaseDir: filepath.Join(packpath.SidecarDir(absOutputPath), "receipts", "pull"),
	}
	receiptPath, err := writer.Write(receipt)
	if err != nil {
		// Log but don't fail - receipt is for audit, not critical path
		_, _ = fmt.Fprintf(stderr, "Warning: failed to write receipt: %v\n", err)
	}
	result.ReceiptPath = receiptPath

	return result, nil
}

// downloadPackWithProgress downloads the pack file using the provided download info,
// optionally reporting progress via a callback. Returns the SHA256 digest of the downloaded file.
//
// SECURITY: This function validates URLs from untrusted adapter responses to prevent SSRF.
// Only HTTPS URLs are allowed. HTTP to localhost requires explicit opt-in via transport config.
// File URLs are allowed for local filesystem remotes, optionally confined to a root directory.
func downloadPackWithProgress(ctx context.Context, outputPath string, download remote.DownloadInfo, expectedSize int64, transport config.RemoteTransport, onProgress DownloadProgressCallback) (string, error) {
	// Check for file:// URL (local filesystem remote)
	parsed, err := url.Parse(download.URL)
	if err != nil {
		return "", fmt.Errorf("invalid download URL: %w", err)
	}

	if parsed.Scheme == "file" {
		return downloadPackFromFile(ctx, outputPath, parsed.Path, expectedSize, transport.FileRoot, onProgress)
	}

	// SECURITY: Validate URL from untrusted adapter response to prevent SSRF.
	// Adapters can return arbitrary URLs; we must validate before fetching.
	if err := validateAdapterURL(download.URL, transport.AllowLoopbackHTTP); err != nil {
		return "", fmt.Errorf("invalid download URL from adapter: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, download.Method, download.URL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	for k, v := range download.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Transport: netpolicy.SecureTransport(),
		Timeout:   30 * time.Minute, // Large file download timeout
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Create output file
	f, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("creating output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Use Content-Length if available, otherwise use expected size from metadata
	totalSize := resp.ContentLength
	if totalSize <= 0 {
		totalSize = expectedSize
	}

	// Create hash writer for digest computation
	hasher := sha256.New()

	// Wrap response body in progress reader if callback provided
	var reader io.Reader = resp.Body
	if onProgress != nil && totalSize > 0 {
		reader = progress.NewReader(resp.Body, totalSize, progress.Callback(onProgress))
	}

	// Defense-in-depth: enforce size limit at read time, not just Content-Length check.
	// A malicious server could lie about Content-Length or stream indefinitely.
	reader = io.LimitReader(reader, limits.MaxPackSizeBytes)

	// Copy to file and hasher simultaneously
	multiWriter := io.MultiWriter(f, hasher)
	if _, err := io.Copy(multiWriter, reader); err != nil {
		return "", fmt.Errorf("writing file: %w", err)
	}

	return fmt.Sprintf("sha256:%x", hasher.Sum(nil)), nil
}

// downloadPackFromFile handles file:// URLs by copying from the local path.
//
// SECURITY: Uses fd-based operations with O_NOFOLLOW to prevent symlink attacks.
// Requires fileRoot to be set - file:// URLs are rejected without explicit confinement.
func downloadPackFromFile(ctx context.Context, outputPath, srcPath string, expectedSize int64, fileRoot string, onProgress DownloadProgressCallback) (string, error) {
	// SECURITY: Require file_root for file:// URLs.
	// This forces users to explicitly configure where file operations are allowed,
	// preventing adapters from directing reads to arbitrary locations.
	if fileRoot == "" {
		return "", fmt.Errorf("file:// URLs require transport.file_root to be configured in the remote")
	}

	if err := validateFileRoot(srcPath, fileRoot); err != nil {
		return "", err
	}

	// SECURITY: Use safefile.OpenForRead which uses O_NOFOLLOW to atomically refuse symlinks.
	// This prevents TOCTOU attacks where an attacker replaces a file with a symlink
	// between validation and open.
	src, err := safefile.OpenForRead(srcPath)
	if err != nil {
		return "", fmt.Errorf("opening source file: %w", err)
	}
	defer func() { _ = src.Close() }()

	info, err := src.Stat()
	if err != nil {
		return "", fmt.Errorf("getting source size: %w", err)
	}

	totalSize := info.Size()
	if totalSize <= 0 {
		totalSize = expectedSize
	}

	// Create output file
	dst, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("creating output file: %w", err)
	}
	defer func() { _ = dst.Close() }()

	// Create hash writer for digest computation
	hasher := sha256.New()

	// Wrap source in progress reader if callback provided
	var reader io.Reader = src
	if onProgress != nil && totalSize > 0 {
		reader = progress.NewReader(src, totalSize, progress.Callback(onProgress))
	}

	// Defense-in-depth: enforce size limit
	reader = io.LimitReader(reader, limits.MaxPackSizeBytes)

	// Copy to file and hasher simultaneously
	multiWriter := io.MultiWriter(dst, hasher)
	if _, err := io.Copy(multiWriter, reader); err != nil {
		return "", fmt.Errorf("copying file: %w", err)
	}

	return fmt.Sprintf("sha256:%x", hasher.Sum(nil)), nil
}

// sanitizeStreamName converts a stream identifier to a safe filename.
// Example: "myorg/prod" -> "myorg-prod"
func sanitizeStreamName(stream string) string {
	result := make([]byte, 0, len(stream))
	for i := 0; i < len(stream); i++ {
		c := stream[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result = append(result, c)
		} else {
			result = append(result, '-')
		}
	}
	if len(result) == 0 {
		return "pack"
	}
	return string(result)
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
