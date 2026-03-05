package push

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/component/config"
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

// StepCallback is called when a push step starts or completes.
// step is the step name, started indicates whether the step is starting (true) or done (false).
type StepCallback func(step string, started bool)

// UploadProgressCallback is called periodically during upload with bytes written and total.
type UploadProgressCallback func(written, total int64)

// Options configures a push operation.
type Options struct {
	// Secure defaults.
	Secure struct {
		Frozen bool
	}
	// Explicit insecure overrides.
	Unsafe struct {
		AllowUnpinned bool
	}

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
	stderr, err := validateAndNormalizePushOptions(opts)
	if err != nil {
		return nil, err
	}

	step := newPushStepEmitter(opts.OnStep)
	absPackPath, packDigest, packSize, err := verifyPushPack(opts.PackPath, step)
	if err != nil {
		return nil, err
	}
	projectRoot, cfg, remoteCfg, err := loadPushRemoteConfig(opts, step)
	if err != nil {
		return nil, err
	}
	exec, caps, err := preparePushAdapter(ctx, opts, step, stderr, projectRoot, cfg, remoteCfg)
	if err != nil {
		return nil, err
	}
	defer exec.Close()
	if !caps.SupportsPrepareFinalize() {
		return nil, fmt.Errorf("adapter does not support prepare/finalize upload protocol")
	}
	target := buildPushTarget(remoteCfg, opts)
	releaseInfo := buildReleaseInfo(remoteCfg, opts)
	prepResp, err := runPushPrepare(ctx, exec, opts.Remote, target, absPackPath, packDigest, packSize, releaseInfo, step)
	if err != nil {
		return nil, err
	}
	if err := maybeRunPushUpload(ctx, absPackPath, prepResp.Upload, remoteCfg.Transport, opts.OnUploadProgress, step); err != nil {
		return nil, err
	}
	finalResp, err := runPushFinalize(ctx, exec, opts.Remote, target, absPackPath, packDigest, packSize, prepResp.FinalizeToken, step)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Release: &finalResp.Release,
		Links:   finalResp.Links,
	}
	if err := maybeSyncPushRuns(ctx, exec, target, packDigest, absPackPath, remoteCfg, opts, caps, step, result); err != nil {
		return result, err
	}

	result.ReceiptPath = writePushReceipt(opts.Remote, target, absPackPath, packDigest, packSize, finalResp, result, stderr)

	return result, nil
}

func validateAndNormalizePushOptions(opts Options) (io.Writer, error) {
	if opts.Remote == "" {
		return nil, fmt.Errorf("remote is required")
	}
	if err := (securitypolicy.ExecutionPolicy{
		Frozen:        opts.Secure.Frozen,
		AllowUnpinned: opts.Unsafe.AllowUnpinned,
	}).Enforce(); err != nil {
		return nil, err
	}
	if err := securitypolicy.EnforceStrictProduction("push", opts.Unsafe.AllowUnpinned); err != nil {
		return nil, err
	}
	if opts.PackPath == "" {
		return nil, fmt.Errorf("pack path is required")
	}
	if opts.Stderr != nil {
		return opts.Stderr, nil
	}
	return os.Stderr, nil
}

func maybeSyncPushRuns(
	ctx context.Context,
	exec *remote.Executor,
	target remote.TargetConfig,
	packDigest, absPackPath string,
	remoteCfg *config.RemoteConfig,
	opts Options,
	caps *remote.Capabilities,
	step StepCallback,
	result *Result,
) error {
	if opts.NoRuns || !remoteCfg.Runs.SyncEnabled() || !caps.SupportsRunsSync() {
		return nil
	}
	step("Syncing runs", true)
	syncedRuns, failedRuns, syncErr := syncRuns(ctx, exec, target, packDigest, absPackPath, remoteCfg, opts.RunsPaths)
	result.SyncedRuns = syncedRuns
	result.FailedRuns = failedRuns
	step("Syncing runs", false)
	if syncErr == nil || !remoteCfg.Runs.RequireSuccess {
		return nil
	}
	return fmt.Errorf("run sync failed (require_success=true): %w", syncErr)
}

func newPushStepEmitter(cb StepCallback) StepCallback {
	return func(name string, started bool) {
		if cb != nil {
			cb(name, started)
		}
	}
}

func verifyPushPack(packPath string, step StepCallback) (string, string, int64, error) {
	step("Verifying pack integrity", true)
	defer step("Verifying pack integrity", false)

	absPackPath, err := filepath.Abs(packPath)
	if err != nil {
		return "", "", 0, fmt.Errorf("resolving pack path: %w", err)
	}
	p, err := pack.Open(absPackPath)
	if err != nil {
		return "", "", 0, fmt.Errorf("opening pack: %w", err)
	}
	defer func() { _ = p.Close() }()

	if err := p.VerifyIntegrity(); err != nil {
		return "", "", 0, fmt.Errorf("pack verification failed: %w", err)
	}
	packInfo, err := os.Stat(absPackPath)
	if err != nil {
		return "", "", 0, fmt.Errorf("getting pack info: %w", err)
	}
	return absPackPath, p.Manifest().PackDigest, packInfo.Size(), nil
}

func loadPushRemoteConfig(opts Options, step StepCallback) (string, *config.JobConfig, *config.RemoteConfig, error) {
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

func preparePushAdapter(ctx context.Context, opts Options, step StepCallback, stderr io.Writer, projectRoot string, cfg *config.JobConfig, remoteCfg *config.RemoteConfig) (*remote.Executor, *remote.Capabilities, error) {
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

func buildPushTarget(remoteCfg *config.RemoteConfig, opts Options) remote.TargetConfig {
	target := remote.TargetConfig{
		Workspace:   remoteCfg.Target.Workspace,
		Environment: remoteCfg.Target.Environment,
	}
	if opts.Workspace != "" {
		target.Workspace = opts.Workspace
	}
	return target
}

func buildReleaseInfo(remoteCfg *config.RemoteConfig, opts Options) remote.ReleaseInfo {
	labels := append([]string{}, remoteCfg.Release.Labels...)
	labels = append(labels, opts.Labels...)
	releaseInfo := remote.ReleaseInfo{
		Labels: labels,
		Notes:  opts.Notes,
	}
	if releaseInfo.Notes == "" {
		releaseInfo.Notes = remoteCfg.Release.Notes
	}
	if remoteCfg.Release.Source != nil {
		releaseInfo.Source = buildSourceInfo(remoteCfg.Release.Source)
	}
	return releaseInfo
}

func runPushPrepare(ctx context.Context, exec *remote.Executor, remoteName string, target remote.TargetConfig, absPackPath, packDigest string, packSize int64, releaseInfo remote.ReleaseInfo, step StepCallback) (*remote.PrepareResponse, error) {
	step("Preparing upload", true)
	defer step("Preparing upload", false)

	// Compute MD5 checksum for upload verification (base64-encoded for S3)
	checksum, err := computePackChecksum(absPackPath)
	if err != nil {
		return nil, fmt.Errorf("computing checksum: %w", err)
	}

	prepResp, err := exec.Prepare(ctx, &remote.PrepareRequest{
		Remote: remoteName,
		Target: target,
		Pack: remote.PackInfo{
			Path:      absPackPath,
			Digest:    packDigest,
			SizeBytes: packSize,
			Checksum:  checksum,
		},
		Release: releaseInfo,
	})
	if err != nil {
		return nil, fmt.Errorf("push.prepare failed: %w", err)
	}
	return prepResp, nil
}

// computePackChecksum computes the base64-encoded MD5 checksum of a pack file.
// This format is required by S3's Content-MD5 header for upload verification.
func computePackChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func maybeRunPushUpload(ctx context.Context, absPackPath string, upload remote.UploadInfo, transport config.RemoteTransport, onProgress UploadProgressCallback, step StepCallback) error {
	if upload.Method == "skip" {
		return nil
	}
	step("Uploading pack", true)
	defer step("Uploading pack", false)
	if err := uploadPackWithProgress(ctx, absPackPath, upload, transport, onProgress); err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	return nil
}

func runPushFinalize(ctx context.Context, exec *remote.Executor, remoteName string, target remote.TargetConfig, absPackPath, packDigest string, packSize int64, finalizeToken string, step StepCallback) (*remote.FinalizeResponse, error) {
	step("Finalizing release", true)
	defer step("Finalizing release", false)
	finalResp, err := exec.Finalize(ctx, &remote.FinalizeRequest{
		Remote: remoteName,
		Target: target,
		Pack: remote.PackInfo{
			Path:      absPackPath,
			Digest:    packDigest,
			SizeBytes: packSize,
		},
		FinalizeToken: finalizeToken,
	})
	if err != nil {
		return nil, fmt.Errorf("push.finalize failed: %w", err)
	}
	return finalResp, nil
}

func writePushReceipt(remoteName string, target remote.TargetConfig, absPackPath, packDigest string, packSize int64, finalResp *remote.FinalizeResponse, result *Result, stderr io.Writer) string {
	receipt := NewReceipt(
		remoteName,
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
		_, _ = fmt.Fprintf(stderr, "Warning: failed to write receipt: %v\n", err)
	}
	return receiptPath
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
	parsed, err := url.Parse(upload.URL)
	if err != nil {
		return fmt.Errorf("invalid upload URL: %w", err)
	}
	if parsed.Scheme == "file" {
		return uploadPackToFile(ctx, packPath, parsed.Path, transport.FileRoot, onProgress)
	}
	if err := validateAdapterURL(upload.URL, transport.AllowLoopbackHTTP); err != nil {
		return fmt.Errorf("invalid upload URL from adapter: %w", err)
	}
	resp, err := performUploadRequest(ctx, packPath, upload, onProgress)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return ensureSuccessfulUploadResponse(resp)
}

func performUploadRequest(ctx context.Context, packPath string, upload remote.UploadInfo, onProgress UploadProgressCallback) (*http.Response, error) {
	f, err := os.Open(packPath)
	if err != nil {
		return nil, fmt.Errorf("opening pack: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("getting pack size: %w", err)
	}

	var body io.Reader = f
	if onProgress != nil {
		body = progress.NewReader(f, info.Size(), progress.Callback(onProgress))
	}
	req, err := http.NewRequestWithContext(ctx, upload.Method, upload.URL, body)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.ContentLength = info.Size()
	for k, v := range upload.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Transport: netpolicy.SecureTransport(), Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("upload request: %w", err)
	}
	return resp, nil
}

func ensureSuccessfulUploadResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(respBody))
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
	// Default paths match where CreateRunDir places results:
	// - tools/**/result.json for pack-based tool runs
	// - runs/**/result.json for packless runs (stored in sidecar)
	paths := cfg.Runs.Paths
	if len(paths) == 0 {
		paths = []string{"tools/**/result.json", "runs/**/result.json"}
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

		matches, err := globWithDoublestar(pattern)
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

// globWithDoublestar handles glob patterns with ** for recursive directory matching.
// Unlike filepath.Glob, this properly handles ** to match any number of directories.
func globWithDoublestar(pattern string) ([]string, error) {
	// If pattern doesn't contain **, use standard glob
	if !strings.Contains(pattern, "**") {
		return filepath.Glob(pattern)
	}

	var matches []string
	baseDir := doublestarBaseDir(pattern)
	err := filepath.WalkDir(baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if d.IsDir() {
			return nil
		}

		matched, matchErr := matchDoublestar(pattern, path)
		if matchErr != nil {
			return nil
		}
		if matched {
			matches = append(matches, path)
		}
		return nil
	})

	return matches, err
}

func doublestarBaseDir(pattern string) string {
	cleanPattern := filepath.Clean(pattern)
	sep := string(filepath.Separator)
	parts := strings.Split(cleanPattern, sep)
	var baseParts []string
	for _, part := range parts {
		if strings.ContainsAny(part, "*?[") {
			break
		}
		baseParts = append(baseParts, part)
	}
	if len(baseParts) == 0 {
		if filepath.IsAbs(cleanPattern) {
			return sep
		}
		return "."
	}
	baseDir := filepath.Join(baseParts...)
	if filepath.IsAbs(cleanPattern) {
		return sep + baseDir
	}
	return baseDir
}

func matchDoublestar(pattern, p string) (bool, error) {
	patternParts := strings.Split(filepath.ToSlash(filepath.Clean(pattern)), "/")
	pathParts := strings.Split(filepath.ToSlash(filepath.Clean(p)), "/")
	return matchDoublestarParts(patternParts, pathParts)
}

func matchDoublestarParts(patternParts, pathParts []string) (bool, error) {
	if len(patternParts) == 0 {
		return len(pathParts) == 0, nil
	}

	part := patternParts[0]
	if part == "**" {
		if len(patternParts) == 1 {
			return true, nil
		}
		for i := 0; i <= len(pathParts); i++ {
			matched, err := matchDoublestarParts(patternParts[1:], pathParts[i:])
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	}

	if len(pathParts) == 0 {
		return false, nil
	}

	matched, err := path.Match(part, pathParts[0])
	if err != nil {
		return false, err
	}
	if !matched {
		return false, nil
	}

	return matchDoublestarParts(patternParts[1:], pathParts[1:])
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
	if err := adapterurl.Validate(rawURL, allowLoopbackHTTP); err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventSSRFBlockedURL,
			Component:   "remote_adapter",
			Description: "blocked adapter-provided push URL",
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
