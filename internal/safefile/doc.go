// Package safefile provides secure filesystem operations with symlink protection.
//
// This is the primary package for all file I/O in security-sensitive contexts.
// It combines path validation, symlink protection, and atomic operations.
//
// # Which Function Should I Use?
//
// Writing files:
//
//	safefile.WriteFile(baseDir, path, data)         // Default: creates dirs, atomic, 0755/0644
//	safefile.WriteFilePrivate(baseDir, path, data)  // For secrets: 0700/0600 permissions
//	safefile.WriteFileExclusive(baseDir, path, data) // Fail if file already exists
//	safefile.WriteJSON(baseDir, path, v)            // Marshal and write atomically
//
// Reading files:
//
//	safefile.ReadFile(path, limits.ConfigFile)      // With size limit, refuses symlinks
//
// Streaming (when you need an io.Reader/Writer):
//
//	safefile.OpenForRead(path)                      // Returns *os.File, refuses symlinks
//	safefile.OpenForWrite(path)                     // Returns *os.File, refuses symlinks
//
// Directories:
//
//	safefile.MkdirAll(baseDir, path)                // Create with symlink protection
//
// Path validation (pure string operations, no I/O):
//
//	safefile.ValidatePath(baseDir, relPath)         // Check path stays within baseDir
//	safefile.ContainsSymlink(path)                  // Check if any component is a symlink
//
// # Security Properties
//
// All operations in this package:
//   - Refuse to follow symlinks (using O_NOFOLLOW on Unix)
//   - Validate path containment to prevent directory traversal
//   - Use atomic operations where possible (temp file + rename)
//   - Pin file descriptors to prevent TOCTOU race conditions
//
// # Base Directory
//
// Most write operations require a baseDir parameter. This is the trusted root
// directory that the operation must stay within. All paths are validated to
// ensure they don't escape this directory via ".." or symlinks.
package safefile
