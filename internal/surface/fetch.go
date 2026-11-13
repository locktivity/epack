package surface

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/boundedio"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
)

// FetchTimeout bounds one description download. Descriptions run to tens of
// megabytes, so it is longer than the default HTTP timeout.
const FetchTimeout = 5 * time.Minute

// Digest is the SHA-256 of a description file, or, for a directory, of the
// digests of its description files in name order, each followed by a
// newline, as hex.
func Digest(path string) (string, error) {
	files, err := DescriptionFiles(path)
	if err != nil {
		return "", err
	}
	if len(files) == 1 && files[0] == path {
		data, err := safefile.ReadFile(path, limits.Artifact)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	}
	h := sha256.New()
	for _, file := range files {
		data, err := safefile.ReadFile(file, limits.Artifact)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		_, _ = fmt.Fprintf(h, "%s\n", hex.EncodeToString(sum[:]))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Fetch downloads a pinned description into cacheDir and returns its local
// path: a file, or a directory when the entry lists files under a base
// URL. A copy already in the cache whose digest matches the entry's pin is
// used as it is. The URL must be https, or http to a loopback host.
func Fetch(ctx context.Context, ref SpecRef, cacheDir string, client *http.Client) (string, error) {
	if ref.URL == "" {
		return "", fmt.Errorf("%s has no url to fetch", ref.Label())
	}
	base, err := url.Parse(ref.URL)
	if err != nil {
		return "", fmt.Errorf("%s: url: %w", ref.Label(), err)
	}
	if base.Scheme != "https" && (base.Scheme != "http" || !isLoopback(base.Hostname())) {
		return "", fmt.Errorf("%s: url %s must use https", ref.Label(), ref.URL)
	}
	if client == nil {
		client = &http.Client{Timeout: FetchTimeout}
	}
	sum := sha256.Sum256([]byte(ref.URL))
	rel := filepath.Join("surface", hex.EncodeToString(sum[:16]))
	dir := filepath.Join(cacheDir, rel)

	if len(ref.Files) == 0 {
		name := path.Base(base.Path)
		if name == "" || name == "/" || name == "." {
			name = "description"
		}
		target := filepath.Join(dir, name)
		if cached(target, ref.SHA256) {
			return target, nil
		}
		if err := download(ctx, client, ref.URL, cacheDir, filepath.Join(rel, name)); err != nil {
			return "", fmt.Errorf("%s: %w", ref.Label(), err)
		}
		return target, nil
	}
	if !strings.HasSuffix(ref.URL, "/") {
		return "", fmt.Errorf("%s: a url with files must end in /", ref.Label())
	}
	for _, file := range ref.Files {
		if file == "" || file != path.Base(file) || strings.HasPrefix(file, ".") {
			return "", fmt.Errorf("%s: files holds %q, which is not a plain file name", ref.Label(), file)
		}
	}
	if cached(dir, ref.SHA256) {
		return dir, nil
	}
	for _, file := range ref.Files {
		if err := download(ctx, client, ref.URL+file, cacheDir, filepath.Join(rel, file)); err != nil {
			return "", fmt.Errorf("%s: %w", ref.Label(), err)
		}
	}
	return dir, nil
}

// cached reports whether a description at p is in the cache with the
// pinned digest. With no pin, any copy counts.
func cached(p, pin string) bool {
	if _, err := os.Stat(p); err != nil {
		return false
	}
	if pin == "" {
		return true
	}
	got, err := Digest(p)
	return err == nil && strings.EqualFold(got, pin)
}

func download(ctx context.Context, client *http.Client, rawURL, baseDir, rel string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "epack/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: HTTP %d", rawURL, resp.StatusCode)
	}
	data, err := boundedio.ReadReaderWithLimit(resp.Body, "description", limits.Artifact)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(baseDir, rel)), 0o755); err != nil {
		return err
	}
	return safefile.WriteFile(baseDir, rel, data)
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
