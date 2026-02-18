package pack

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/digest"
	"github.com/locktivity/epack/internal/limits"
)

// ReadArtifact reads an artifact and verifies its digest and size against the manifest.
func (p *Pack) ReadArtifact(path string) ([]byte, error) {
	return p.ReadArtifactWithBudget(path, nil)
}

// ReadArtifactWithBudget reads an artifact with integrity verification,
// tracking reads against the provided budget.
//
// If budget is nil, only per-artifact limits are enforced.
func (p *Pack) ReadArtifactWithBudget(path string, budget *ReadBudget) ([]byte, error) {
	artifact := p.findArtifact(path)
	if artifact == nil {
		return nil, errors.E(errors.MissingEntry,
			fmt.Sprintf("artifact %q not found in manifest", path), nil)
	}

	data, err := p.ReadFileUntrustedWithBudget(path, budget)
	if err != nil {
		return nil, err
	}

	if err := verifyArtifactData(path, artifact, data); err != nil {
		return nil, err
	}

	return data, nil
}

// verifyArtifactData checks an artifact's size and digest against manifest values.
// SECURITY: Uses constant-time comparison via digest.Equal to prevent timing attacks.
func verifyArtifactData(path string, artifact *Artifact, data []byte) error {
	if artifact.Size != nil {
		expectedSize, err := artifact.Size.Int64()
		if err != nil {
			return errors.E(errors.InvalidManifest,
				fmt.Sprintf("artifact %q has invalid size in manifest", path), err)
		}
		if int64(len(data)) != expectedSize {
			return errors.E(errors.SizeMismatch,
				fmt.Sprintf("artifact %q size mismatch: manifest declares %d bytes, got %d bytes",
					path, expectedSize, len(data)), nil)
		}
	}

	computedDigest := computeSHA256(data)
	if !verifyDigest(artifact.Digest, computedDigest) {
		return errors.E(errors.DigestMismatch,
			fmt.Sprintf("artifact %q digest mismatch: manifest declares %s, computed %s",
				path, artifact.Digest, computedDigest), nil)
	}

	return nil
}

// findArtifact looks up an artifact by path in the manifest.
func (p *Pack) findArtifact(path string) *Artifact {
	for i := range p.manifest.Artifacts {
		if p.manifest.Artifacts[i].Path == path {
			return &p.manifest.Artifacts[i]
		}
	}
	return nil
}

// VerifyPackDigest verifies pack_digest matches the canonical artifact list hash.
// Does not verify artifact file contents; use VerifyAllArtifacts for that.
// SECURITY: Uses constant-time comparison via digest.Equal to prevent timing attacks.
func (p *Pack) VerifyPackDigest() error {
	canonical := BuildCanonicalArtifactList(p.manifest)
	computedDigest := HashCanonicalList(canonical)
	if !verifyDigest(p.manifest.PackDigest, computedDigest) {
		return errors.E(errors.DigestMismatch,
			fmt.Sprintf("pack_digest mismatch: manifest declares %s, computed %s",
				p.manifest.PackDigest, computedDigest), nil)
	}

	return nil
}

// VerifyAllArtifacts verifies all embedded artifact digests and sizes.
// Enforces aggregate size budget.
//
// SECURITY: This is a low-level function that only verifies individual artifact
// integrity. It does NOT verify pack_digest, which ensures manifest-level coverage.
// Use VerifyIntegrity() for complete verification including pack_digest.
//
// Only use this directly when:
//   - You've already verified pack_digest separately, OR
//   - You're implementing custom verification logic that handles pack_digest elsewhere
//
// In most cases, prefer VerifyIntegrity() which calls both this and VerifyPackDigest().
func (p *Pack) VerifyAllArtifacts() error {
	var totalBytesRead int64

	for i := range p.manifest.Artifacts {
		artifact := &p.manifest.Artifacts[i]
		if artifact.Type != "embedded" {
			continue
		}

		data, err := p.ReadFileUntrusted(artifact.Path)
		if err != nil {
			return err
		}

		if err := verifyArtifactData(artifact.Path, artifact, data); err != nil {
			return err
		}

		totalBytesRead += int64(len(data))
		if totalBytesRead > limits.MaxPackSizeBytes {
			return errors.E(errors.ZipBomb,
				fmt.Sprintf("aggregate artifact size %d exceeds pack limit %d bytes",
					totalBytesRead, limits.MaxPackSizeBytes), nil)
		}
	}

	return nil
}

// VerifyIntegrity verifies complete pack integrity: artifact digests, sizes, and pack_digest.
//
// This is the primary integrity verification API. It ensures:
//   - All embedded artifacts have correct digests and sizes
//   - The pack_digest matches the canonical artifact list hash
//   - Aggregate read budget is not exceeded (DoS prevention)
//
// SECURITY: This is the recommended verification entrypoint. Using VerifyAllArtifacts
// or VerifyPackDigest individually risks partial verification.
func (p *Pack) VerifyIntegrity() error {
	if err := p.VerifyAllArtifacts(); err != nil {
		return err
	}
	return p.VerifyPackDigest()
}

// ReadArtifactTo streams an artifact to a writer with integrity verification.
// This is the recommended method for processing large artifacts without loading
// them entirely into memory.
//
// The artifact digest is verified after all bytes are written. If verification
// fails, an error is returned. The caller should handle this by discarding any
// output already written (e.g., by truncating a file or discarding a buffer).
//
// Example:
//
//	f, _ := os.Create("output.json")
//	defer f.Close()
//	n, err := p.ReadArtifactTo(f, "artifacts/data.json")
//	if err != nil {
//	    os.Remove("output.json") // Discard corrupted output
//	    return err
//	}
func (p *Pack) ReadArtifactTo(w io.Writer, path string) (int64, error) {
	reader, err := p.OpenArtifact(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = reader.Close() }()

	n, copyErr := io.Copy(w, reader)
	closeErr := reader.Close() // Close verifies the digest

	if copyErr != nil {
		return n, copyErr
	}
	if closeErr != nil {
		return n, closeErr
	}
	return n, nil
}

// OpenArtifact returns a reader that verifies the artifact digest on Close().
// This is useful for streaming large artifacts without loading them entirely
// into memory, while still ensuring integrity.
//
// IMPORTANT: The digest is verified when Close() is called. If you don't read
// all bytes before closing, truncation attacks won't be detected. Always read
// to EOF before closing, or use ReadArtifact for smaller artifacts.
//
// The returned reader enforces per-artifact size limits. For pack-wide limits,
// use OpenArtifactWithBudget.
func (p *Pack) OpenArtifact(path string) (io.ReadCloser, error) {
	return p.OpenArtifactWithBudget(path, nil)
}

// OpenArtifactWithBudget returns a reader that verifies digest on Close(),
// tracking reads against the provided budget.
//
// IMPORTANT: See OpenArtifact for usage notes about digest verification timing.
func (p *Pack) OpenArtifactWithBudget(path string, budget *ReadBudget) (io.ReadCloser, error) {
	artifact := p.findArtifact(path)
	if artifact == nil {
		return nil, errors.E(errors.MissingEntry,
			fmt.Sprintf("artifact %q not found in manifest", path), nil)
	}

	reader, err := p.OpenFileUntrustedWithBudget(path, budget)
	if err != nil {
		return nil, err
	}

	return &verifyingReader{
		reader:       reader,
		path:         path,
		expectedSize: artifact.Size,
		digest:       artifact.Digest,
		hasher:       digest.NewHasher(),
	}, nil
}

// verifyingReader wraps a reader and verifies digest on Close().
type verifyingReader struct {
	reader       io.ReadCloser
	path         string
	expectedSize *json.Number
	digest       string
	hasher       *digest.Hasher
	bytesRead    int64
	closed       bool
	readErr      error // stores first read error
}

func (r *verifyingReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, errors.E(errors.InvalidInput, "read after close", nil)
	}

	n, err := r.reader.Read(p)
	if n > 0 {
		r.bytesRead += int64(n)
		_, _ = r.hasher.Write(p[:n])
	}
	if err != nil && err != io.EOF && r.readErr == nil {
		r.readErr = err
	}
	return n, err
}

// Close verifies the digest and closes the underlying reader.
// Returns an error if the digest doesn't match or size is wrong.
// If the underlying reader returned an error during Read, that error is returned.
func (r *verifyingReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true

	closeErr := r.reader.Close()

	// If there was a read error, return that (likely more informative)
	if r.readErr != nil {
		return r.readErr
	}

	// Verify size if specified
	if r.expectedSize != nil {
		expectedBytes, err := r.expectedSize.Int64()
		if err != nil {
			return errors.E(errors.InvalidManifest,
				fmt.Sprintf("artifact %q has invalid size in manifest", r.path), err)
		}
		if r.bytesRead != expectedBytes {
			return errors.E(errors.SizeMismatch,
				fmt.Sprintf("artifact %q size mismatch: manifest declares %d bytes, got %d bytes",
					r.path, expectedBytes, r.bytesRead), nil)
		}
	}

	// Verify digest
	computedDigest := r.hasher.Digest().String()
	if !verifyDigest(r.digest, computedDigest) {
		return errors.E(errors.DigestMismatch,
			fmt.Sprintf("artifact %q digest mismatch: manifest declares %s, computed %s",
				r.path, r.digest, computedDigest), nil)
	}

	return closeErr
}
