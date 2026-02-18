// Package project provides utilities for finding and working with epack project roots.
//
// This package is a Layer 0 utility that can be imported by any layer without
// creating dependency cycles. It provides the core logic for locating epack.yaml
// in the directory hierarchy.
//
// # Security
//
// FindRoot uses os.Lstat to detect symlinks, preventing TOCTOU attacks where
// an attacker could create a symlink epack.yaml pointing to a malicious config.
package project
