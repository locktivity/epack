// Package boundedio provides IO utilities with security limits.
//
// This package consolidates the common pattern of size-limited file reading
// that was previously duplicated across multiple packages. All functions
// implement defense-in-depth against:
//
//   - Memory exhaustion from large files
//   - TOCTOU races (file size changes between check and read)
//   - Truncation attacks
//
// The standard pattern used throughout is:
//  1. Open file
//  2. Check size via Fstat on open fd (not separate Stat call)
//  3. Use LimitReader(maxBytes+1) as defense-in-depth
//  4. Verify final length to catch growth during read
//
// This package does NOT handle symlink safety - use safefile for that.
package boundedio
