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
	"time"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/netpolicy"
	"github.com/locktivity/epack/internal/netpolicy/adapterurl"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/progress"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/pack"
)

// StepCallback is called when a pull step starts or completes.
// step is the step name, started indicates whether the step is starting (true) or done (false).
type StepCallback func(step string, started bool)

// DownloadProgressCallback is called periodically during download with bytes read and total.
type DownloadProgressCallback func(read, total int64)

// Options configures a pull operation.
type Options struct {
	// Secure defaults.
	Secure struct {
		Frozen bool
	}
	// Explicit insecure overrides.
	Unsafe struct {
		AllowUnpinned bool
	}

	// Remote is the name of the remote to pull from (required).
	Remote string

	// Ref specifies which pack to pull (required).
	// Exactly one of Digest, ReleaseID, Version, or Latest should be set.
	Ref remote.PackRef

	// OutputPath is the destination path for the downloaded pack.
	// If empty, defaults to ./<stream>.epack
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
	stderr, err := validateAndNormalizePullOptions(&opts)
	if err != nil {
		return nil, err
	}
	step := newPullStepEmitter(opts.OnStep)
	projectRoot, cfg, remoteCfg, err := loadPullRemoteConfig(opts, step)
	if err != nil {
		return nil, err
	}

	exec, caps, err := preparePullAdapter(ctx, opts, step, stderr, projectRoot, cfg, remoteCfg)
	if err != nil {
		return nil, err
	}
	defer exec.Close()
	if !caps.SupportsPull() {
		return nil, fmt.Errorf("adapter does not support pull operations")
	}
	target := buildPullTarget(remoteCfg, opts)
	prepResp, absOutputPath, err := executePullTransfer(ctx, exec, opts, target, remoteCfg.Transport, step)
	if err != nil {
		return nil, err
	}

	result := &Result{
		OutputPath: absOutputPath,
		Pack:       &prepResp.Pack,
	}

	if err := maybeVerifyPulledPack(absOutputPath, opts.Verify, step, result); err != nil {
		return nil, err
	}
	finalizePull(ctx, exec, opts.Remote, target, prepResp, stderr, step)
	result.ReceiptPath = writePullReceipt(opts.Remote, target, absOutputPath, &prepResp.Pack, result.Verified, stderr)

	return result, nil
}

func executePullTransfer(
	ctx context.Context,
	exec *remote.Executor,
	opts Options,
	target remote.TargetConfig,
	transport config.RemoteTransport,
	step StepCallback,
) (*remote.PullPrepareResponse, string, error) {
	prepResp, err := runPullPrepare(ctx, exec, opts, target, step)
	if err != nil {
		return nil, "", err
	}
	absOutputPath, err := resolvePullOutputPath(opts, prepResp.Pack.Stream)
	if err != nil {
		return nil, "", err
	}
	if err := ensurePullOutputWritable(absOutputPath, opts.OutputPath, opts.Force); err != nil {
		return nil, "", err
	}
	downloadedDigest, err := runPullDownload(ctx, absOutputPath, prepResp, transport, opts.OnDownloadProgress, step)
	if err != nil {
		return nil, "", err
	}
	if err := verifyPullDigest(prepResp.Pack.Digest, downloadedDigest, absOutputPath); err != nil {
		return nil, "", err
	}
	return prepResp, absOutputPath, nil
}

func validateAndNormalizePullOptions(opts *Options) (io.Writer, error) {
	if opts.Remote == "" {
		return nil, fmt.Errorf("remote is required")
	}
	if err := (securitypolicy.ExecutionPolicy{
		Frozen:        opts.Secure.Frozen,
		AllowUnpinned: opts.Unsafe.AllowUnpinned,
	}).Enforce(); err != nil {
		return nil, err
	}
	if err := securitypolicy.EnforceStrictProduction("pull", opts.Unsafe.AllowUnpinned); err != nil {
		return nil, err
	}
	if opts.Ref.Digest == "" && !opts.Ref.Latest && opts.Ref.ReleaseID == "" && opts.Ref.Version == "" {
		opts.Ref.Latest = true
	}
	if opts.Stderr != nil {
		return opts.Stderr, nil
	}
	return os.Stderr, nil
}

func newPullStepEmitter(cb StepCallback) StepCallback {
	return func(name string, started bool) {
		if cb != nil {
			cb(name, started)
		}
	}
}

func loadPullRemoteConfig(opts Options, step StepCallback) (string, *config.JobConfig, *config.RemoteConfig, error) {
	step("Loading remote configuration", true)
	defer step("Loading remote configuration", false)

	projectRoot, err := project.FindRoot("")
	if err != nil {
		return "", nil, nil, fmt.Errorf("finding project root: %w", err)
	}
	cfg, err := config.Load(filepath.Join(projectRoot, "epack.yaml"))
	if err != nil {
		return "", nil, nil, fmt.Errorf("loading config: %w", err)
	}
	remoteCfg, err := remote.ResolveRemoteConfig(cfg, opts.Remote, opts.Environment)
	if err != nil {
		return "", nil, nil, err
	}
	return projectRoot, cfg, remoteCfg, nil
}

func preparePullAdapter(ctx context.Context, opts Options, step StepCallback, stderr io.Writer, projectRoot string, cfg *config.JobConfig, remoteCfg *config.RemoteConfig) (*remote.Executor, *remote.Capabilities, error) {
	step("Resolving adapter", true)
	defer step("Resolving adapter", false)
	return remote.PrepareAdapterExecutor(
		ctx, projectRoot, opts.Remote, cfg, remoteCfg,
		remote.AdapterExecutorOptions{
			PromptInstall: opts.PromptInstallAdapter,
			Step:          remote.StepCallback(step),
			Stderr:        stderr,
			Verification: remote.VerificationOptions{
				Secure: remote.VerificationSecureOptions{
					Frozen: opts.Secure.Frozen,
				},
				Unsafe: remote.VerificationUnsafeOverrides{
					AllowUnverifiedSource: opts.Unsafe.AllowUnpinned,
				},
			},
		},
	)
}

func buildPullTarget(remoteCfg *config.RemoteConfig, opts Options) remote.TargetConfig {
	target := remote.TargetConfig{
		Workspace:   remoteCfg.Target.Workspace,
		Environment: remoteCfg.Target.Environment,
	}
	if opts.Workspace != "" {
		target.Workspace = opts.Workspace
	}
	return target
}

func runPullPrepare(ctx context.Context, exec *remote.Executor, opts Options, target remote.TargetConfig, step StepCallback) (*remote.PullPrepareResponse, error) {
	step("Preparing download", true)
	defer step("Preparing download", false)
	prepResp, err := exec.PullPrepare(ctx, &remote.PullPrepareRequest{
		Remote: opts.Remote,
		Target: target,
		Ref:    opts.Ref,
	})
	if err != nil {
		return nil, fmt.Errorf("pull.prepare failed: %w", err)
	}
	return prepResp, nil
}

func resolvePullOutputPath(opts Options, stream string) (string, error) {
	outputPath := opts.OutputPath
	if outputPath == "" {
		outputPath = sanitizeStreamName(stream) + packpath.PackExtension
	}
	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return "", fmt.Errorf("resolving output path: %w", err)
	}
	return absOutputPath, nil
}

func ensurePullOutputWritable(absOutputPath, outputPath string, force bool) error {
	if force {
		return nil
	}
	displayPath := outputPath
	if displayPath == "" {
		displayPath = absOutputPath
	}
	if _, err := os.Stat(absOutputPath); err == nil {
		return fmt.Errorf("output file %q already exists (use --force to overwrite)", displayPath)
	}
	return nil
}

func runPullDownload(ctx context.Context, absOutputPath string, prepResp *remote.PullPrepareResponse, transport config.RemoteTransport, onProgress DownloadProgressCallback, step StepCallback) (string, error) {
	step("Downloading pack", true)
	defer step("Downloading pack", false)
	downloadedDigest, err := downloadPackWithProgress(ctx, absOutputPath, prepResp.Download, prepResp.Pack.SizeBytes, transport, onProgress)
	if err != nil {
		_ = os.Remove(absOutputPath)
		return "", fmt.Errorf("download failed: %w", err)
	}
	return downloadedDigest, nil
}

func verifyPullDigest(expectedDigest, actualDigest, absOutputPath string) error {
	if actualDigest == expectedDigest {
		return nil
	}
	_ = os.Remove(absOutputPath)
	return fmt.Errorf("digest mismatch: expected %s, got %s", expectedDigest, actualDigest)
}

func maybeVerifyPulledPack(absOutputPath string, verify bool, step StepCallback, result *Result) error {
	if !verify {
		return nil
	}
	step("Verifying pack integrity", true)
	defer step("Verifying pack integrity", false)

	p, err := pack.Open(absOutputPath)
	if err != nil {
		_ = os.Remove(absOutputPath)
		return fmt.Errorf("opening pack for verification: %w", err)
	}
	if err := p.VerifyIntegrity(); err != nil {
		_ = p.Close()
		_ = os.Remove(absOutputPath)
		return fmt.Errorf("pack verification failed: %w", err)
	}
	_ = p.Close()
	result.Verified = true
	return nil
}

func finalizePull(ctx context.Context, exec *remote.Executor, remoteName string, target remote.TargetConfig, prepResp *remote.PullPrepareResponse, stderr io.Writer, step StepCallback) {
	step("Finalizing download", true)
	defer step("Finalizing download", false)
	_, err := exec.PullFinalize(ctx, &remote.PullFinalizeRequest{
		Remote:        remoteName,
		Target:        target,
		Digest:        prepResp.Pack.Digest,
		FinalizeToken: prepResp.FinalizeToken,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Warning: pull.finalize failed: %v\n", err)
	}
}

func writePullReceipt(remoteName string, target remote.TargetConfig, absOutputPath string, packMeta *remote.PackMetadata, verified bool, stderr io.Writer) string {
	receipt := NewReceipt(remoteName, target, absOutputPath, packMeta, verified)
	writer := &ReceiptWriter{
		BaseDir: filepath.Join(packpath.SidecarDir(absOutputPath), "receipts", "pull"),
	}
	receiptPath, err := writer.Write(receipt)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Warning: failed to write receipt: %v\n", err)
	}
	return receiptPath
}

// downloadPackWithProgress downloads the pack file using the provided download info,
// optionally reporting progress via a callback. Returns the SHA256 digest of the downloaded file.
//
// SECURITY: This function validates URLs from untrusted adapter responses to prevent SSRF.
// Only HTTPS URLs are allowed. HTTP to localhost requires explicit opt-in via transport config.
// File URLs are allowed for local filesystem remotes, optionally confined to a root directory.
func downloadPackWithProgress(ctx context.Context, outputPath string, download remote.DownloadInfo, expectedSize int64, transport config.RemoteTransport, onProgress DownloadProgressCallback) (string, error) {
	parsed, err := url.Parse(download.URL)
	if err != nil {
		return "", fmt.Errorf("invalid download URL: %w", err)
	}

	if parsed.Scheme == "file" {
		return downloadPackFromFile(ctx, outputPath, parsed.Path, expectedSize, transport.FileRoot, onProgress)
	}

	if err := validateAdapterURL(download.URL, transport.AllowLoopbackHTTP); err != nil {
		return "", fmt.Errorf("invalid download URL from adapter: %w", err)
	}
	resp, err := executeDownloadRequest(ctx, download)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if err := ensureSuccessfulDownloadResponse(resp); err != nil {
		return "", err
	}

	totalSize := resp.ContentLength
	if totalSize <= 0 {
		totalSize = expectedSize
	}

	var reader io.Reader = resp.Body
	if onProgress != nil && totalSize > 0 {
		reader = progress.NewReader(resp.Body, totalSize, progress.Callback(onProgress))
	}
	return writeOutputAndDigest(outputPath, reader, "writing file")
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

	var reader io.Reader = src
	if onProgress != nil && totalSize > 0 {
		reader = progress.NewReader(src, totalSize, progress.Callback(onProgress))
	}
	return writeOutputAndDigest(outputPath, reader, "copying file")
}

func executeDownloadRequest(ctx context.Context, download remote.DownloadInfo) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, download.Method, download.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	for k, v := range download.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{
		Transport: netpolicy.SecureTransport(),
		Timeout:   30 * time.Minute,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download request: %w", err)
	}
	return resp, nil
}

func ensureSuccessfulDownloadResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(respBody))
}

func writeOutputAndDigest(outputPath string, reader io.Reader, copyErrPrefix string) (string, error) {
	f, err := safefile.OpenForWrite(outputPath)
	if err != nil {
		return "", fmt.Errorf("creating output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()
	reader = io.LimitReader(reader, limits.MaxPackSizeBytes)
	if _, err := io.Copy(io.MultiWriter(f, hasher), reader); err != nil {
		return "", fmt.Errorf("%s: %w", copyErrPrefix, err)
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
	if err := adapterurl.Validate(rawURL, allowLoopbackHTTP); err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventSSRFBlockedURL,
			Component:   "remote_adapter",
			Description: "blocked adapter-provided pull URL",
			Attrs: map[string]string{
				"url": rawURL,
			},
		})
		return err
	}
	return nil
}

// validateFileRoot validates that filePath is contained within the specified root directory.
//
// SECURITY: This is a string-based pre-check before file operations. The actual file
// operations use O_NOFOLLOW to provide TOCTOU-safe symlink rejection. This pre-check
// adds defense-in-depth by rejecting obvious traversal attempts early.
func validateFileRoot(filePath, fileRoot string) error {
	return adapterurl.ValidateFileRoot(filePath, fileRoot)
}
