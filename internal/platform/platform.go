// Package platform provides platform identification utilities.
//
// This package centralizes GOOS/GOARCH key generation that was previously
// duplicated across multiple packages.
package platform

import (
	"runtime"
	"strings"
)

// Key returns "os/arch" for the given os and arch.
// This is the canonical format for platform identification in lockfiles,
// asset names, and registry lookups.
func Key(goos, goarch string) string {
	return goos + "/" + goarch
}

// Current returns the platform key for the current runtime.
func Current() string {
	return Key(runtime.GOOS, runtime.GOARCH)
}

// Split splits "os/arch" into goos and goarch.
// Returns (platform, "") if no separator is found.
func Split(key string) (goos, goarch string) {
	idx := strings.IndexByte(key, '/')
	if idx < 0 {
		return key, ""
	}
	return key[:idx], key[idx+1:]
}
