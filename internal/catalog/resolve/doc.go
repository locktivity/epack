// Package resolve provides dependency resolution for tool installation.
//
// This package uses the catalog to resolve tool dependencies in topological order.
// It is intentionally separate from internal/component because it requires
// catalog access, which the component package must not import (security boundary).
//
// Use this package for CLI commands that need to discover and install tools
// from the catalog. The resolved dependencies can then be passed to the
// component/sync package for actual installation.
package resolve
