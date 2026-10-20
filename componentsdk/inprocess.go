package componentsdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
)

// InProcessOptions configures RunInProcess.
type InProcessOptions struct {
	// Name is the collector's configured name, as EPACK_COLLECTOR_NAME
	// carries it. It defaults to the spec's name.
	Name string

	// Config is the collector configuration Config returns.
	Config map[string]any

	// Secrets holds the values Secret returns.
	Secrets map[string]string

	// Env holds other environment variables the run reads, such as
	// EPACK_DEADLINE or HTTPS_PROXY.
	Env map[string]string

	// RunID is the run ID a runner would pass in EPACK_RUN_ID.
	RunID string

	// Transport sits under the SDK's HTTP layer in place of the network,
	// for example a replay of recorded responses with a fault injected. It
	// replaces every client's HTTPOptions.Base as well.
	Transport http.RoundTripper

	// Resolver answers the lookups of the collector's Resolvers in place of
	// the network.
	Resolver DNSResolver

	// Dial opens the connections of the collector's Dialers in place of the
	// network.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// RootCAs is the pool Dialer.RootCAs returns, such as that of a test CA
	// that signed the certificates of the servers Dial connects to.
	RootCAs *x509.CertPool

	// Seed fixes the retry jitter, so two runs with the same inputs produce
	// the same output.
	Seed uint64

	// Sleep replaces the waits between retries. The collectortest package
	// passes one that returns at once, so retries cost no time.
	Sleep func(ctx context.Context, d time.Duration) error

	// Clock replaces the run's clock, which Now returns and the result
	// artifact's times come from.
	Clock func() time.Time

	// OutputDir is the staging directory for file artifacts.
	OutputDir string
}

// InProcessResult is what one in-process run produced.
type InProcessResult struct {
	// ExitCode is the exit code RunCollector would have used.
	ExitCode int
	// Artifacts lists the emitted artifacts, the build file and the result
	// artifact last. One emitted without a path carries the path the runner
	// gives it.
	Artifacts []EmittedArtifact
	// Result is the decoded result artifact, or nil when nothing was emitted.
	Result *CollectorResult
	// Build is the decoded build file, or nil when nothing was emitted.
	Build *CollectorBuild
	// Mirrors lists the run's Recorder.Mirror calls, each pair once, in the
	// order first made.
	Mirrors []Mirrored
	// Failure is the failure record, or nil when the run did not fail.
	Failure *ProgressMessage
	// Progress lists the status and progress messages.
	Progress []ProgressMessage
	// Stdout and Stderr are the raw streams.
	Stdout string
	Stderr string
	// Panic holds the panic value and stack when the handler panicked.
	Panic string
	// CredentialHosts lists the HTTPOptions.CredentialHosts of the clients
	// the run built, each distinct list once, in the order the run first
	// built a client with it.
	CredentialHosts [][]string
	// UnlistedCredentials names the operations that sent a credential header
	// through a client built without CredentialHosts.
	UnlistedCredentials []string
}

// EmittedArtifact is one artifact as the runner receives it.
type EmittedArtifact struct {
	Path   string          `json:"path"`
	Schema string          `json:"schema,omitempty"`
	File   string          `json:"file,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`

	// SHA256 and Size describe a file artifact's staged bytes, which
	// RunInProcess reads before the caller can remove the staging
	// directory. SHA256 is hex, and empty when the file could not be read.
	SHA256 string `json:"-"`
	Size   int64  `json:"-"`
}

// RunInProcess runs handler in the calling process the way RunCollector
// does, with its inputs and network taken from opts. It is the seam the
// collectortest package drives; release binaries call RunCollector, which
// has no way to replay responses.
func RunInProcess(spec CollectorSpec, handler CollectorHandler, opts InProcessOptions) (res InProcessResult) {
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		if v, ok := opts.Secrets[key]; ok {
			return v
		}
		return opts.Env[key]
	}
	name := opts.Name
	if name == "" {
		name = spec.Name
	}
	ctx, cancel := context.WithDeadline(context.Background(), collectorDeadline(spec, getenv, time.Now()))
	defer cancel()
	c := &collectorContext{
		ctx:       ctx,
		name:      name,
		outputDir: opts.OutputDir,
		config:    opts.Config,
		spec:      spec,
		out:       &stdout,
		errOut:    &stderr,
		getenv:    getenv,
		progress:  &progressWriter{out: &stdout},
	}
	c.attach(newRun(spec, name, opts.RunID, opts.Transport, opts.Seed))
	c.run.sleep = opts.Sleep
	c.run.resolver = opts.Resolver
	c.run.dial = opts.Dial
	c.run.rootCAs = opts.RootCAs
	if opts.Clock != nil {
		c.run.clock = opts.Clock
		c.run.started = opts.Clock()
	}

	defer func() {
		if p := recover(); p != nil {
			res.Panic = fmt.Sprintf("%v\n%s", p, debug.Stack())
			c.progress.writeFailure(CodeInternal, "", fmt.Sprintf("panic: %v", p))
			res.ExitCode = 2
		}
		res.Stdout = stdout.String()
		res.Stderr = stderr.String()
		res.parseStdout(stdout.Bytes(), name)
		res.recordFiles(opts.OutputDir)
		res.CredentialHosts = c.run.credentialHostLists()
		res.UnlistedCredentials = c.run.unlistedCredentialOps()
		res.Mirrors = c.run.records.mirrored()
	}()
	res.ExitCode = runCollectorWith(c, handler)
	return res
}

// recordFiles notes the size and SHA-256 of each file artifact's staged
// bytes.
func (res *InProcessResult) recordFiles(outputDir string) {
	for i := range res.Artifacts {
		a := &res.Artifacts[i]
		if a.File == "" || outputDir == "" {
			continue
		}
		data, err := safefile.ReadFileBeneath(outputDir, filepath.FromSlash(a.File), limits.Artifact)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		a.SHA256, a.Size = hex.EncodeToString(sum[:]), int64(len(data))
	}
}

var progressType = []byte(`"epack_progress"`)

// parseStdout splits stdout into progress messages and the result envelope,
// as the runner does, and gives each artifact that names no path the
// runner's default for the collector configured as name.
func (res *InProcessResult) parseStdout(out []byte, name string) {
	var envelope bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64<<10), 64<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		var msg ProgressMessage
		// Only a progress message names its type, so the envelope, which
		// holds every artifact, is not decoded twice.
		if len(line) > 0 && line[0] == '{' && bytes.Contains(line, progressType) && json.Unmarshal(line, &msg) == nil && msg.Type == "epack_progress" {
			switch msg.Kind {
			case ProgressKindFailure:
				m := msg
				res.Failure = &m
			default:
				res.Progress = append(res.Progress, msg)
			}
			continue
		}
		envelope.Write(line)
		envelope.WriteByte('\n')
	}
	var result struct {
		Artifacts []EmittedArtifact `json:"artifacts"`
	}
	if bytes.TrimSpace(envelope.Bytes()) == nil || json.Unmarshal(envelope.Bytes(), &result) != nil {
		return
	}
	res.Artifacts = result.Artifacts
	for i, a := range res.Artifacts {
		if a.Path == "" {
			res.Artifacts[i].Path = defaultArtifactPath(name, i)
		}
		switch a.Schema {
		case ResultSchema:
			var decoded CollectorResult
			if json.Unmarshal(a.Data, &decoded) == nil {
				res.Result = &decoded
			}
		case BuildSchema:
			var decoded CollectorBuild
			if json.Unmarshal(a.Data, &decoded) == nil {
				res.Build = &decoded
			}
		}
	}
}
