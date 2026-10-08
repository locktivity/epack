// Package browser opens a URL in the person's default browser.
package browser

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/locktivity/epack/internal/procexec"
)

// ErrNoOpener is returned when no command to open a browser could be found.
var ErrNoOpener = errors.New("no browser opener found")

// ErrUnsupportedURL is returned for anything but an http or https link. The
// openers launch files and applications too, and the link comes from a
// server, so only web links are handed to them.
var ErrUnsupportedURL = errors.New("only http and https links are opened in a browser")

// Validate reports whether Open would hand the link to the browser.
func Validate(link string) error {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedURL, err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if (scheme != "http" && scheme != "https") || parsed.Host == "" {
		return ErrUnsupportedURL
	}
	return nil
}

// Open launches an http or https link in the default browser and returns
// once the opener exits. On WSL2 the Windows browser is reached through
// wslview when present.
func Open(ctx context.Context, link string) error {
	if err := Validate(link); err != nil {
		return err
	}
	link = strings.TrimSpace(link)
	for _, candidate := range openers() {
		path, err := procexec.LookPath(candidate.name)
		if err != nil {
			continue
		}
		return procexec.Run(ctx, procexec.Spec{
			Path:   path,
			Args:   append(append([]string{}, candidate.args...), link),
			Env:    os.Environ(),
			Stdout: nil,
			Stderr: nil,
		})
	}
	return ErrNoOpener
}

type opener struct {
	name string
	args []string
}

func openers() []opener {
	switch runtime.GOOS {
	case "darwin":
		return []opener{{name: "open"}}
	case "windows":
		return []opener{{name: "rundll32", args: []string{"url.dll,FileProtocolHandler"}}}
	default:
		return []opener{{name: "xdg-open"}, {name: "wslview"}, {name: "sensible-browser"}}
	}
}
