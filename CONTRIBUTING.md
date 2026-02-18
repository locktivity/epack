# Contributing to epack

Thank you for your interest in contributing to epack!

Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Before You Start

- **Open an issue first** for significant changes to discuss the approach
- Check existing issues and pull requests to avoid duplicating effort
- Small bug fixes and documentation improvements can go directly to a PR

## Development Setup

```bash
# Clone the repository
git clone https://github.com/locktivity/epack.git
cd epack

# Build all packages
go build ./...

# Run tests
go test ./...

# Build the CLI
go build -o epack ./cmd/epack
```

## Running Tests

```bash
# All tests
go test ./...

# Verbose output
go test -v ./...

# Specific package
go test -v ./pack/...

# Run conformance tests
go test -v ./conformance/...

# Update golden files (when expected output changes)
UPDATE_GOLDEN=1 go test ./cmd/epack/cmd/...
```

## Pull Request Process

1. Fork the repository and create a feature branch
2. Write tests for new functionality
3. Ensure all tests pass: `go test ./...`
4. Run `go vet ./...` and fix any issues
5. Format code with `gofmt -s -w .`
6. Submit a PR with a clear description of the changes

## Code Style

- Run `gofmt` on all code
- Follow standard Go conventions and idioms
- Add doc comments for all exported types, functions, and methods
- Keep functions focused and reasonably sized
- Use meaningful variable and function names

## Commit Messages

Write clear commit messages that explain the "why" behind changes:

```
Add digest verification for merged packs

Previously merged packs did not verify source pack digests
during the merge operation. This adds validation to ensure
source pack integrity before merging.
```

## Changelog

When adding features or fixing bugs, add an entry to CHANGELOG.md under the "Unreleased" section:

```markdown
## [Unreleased]

### NEW FEATURES
- Add `--filter` flag to extract command

### BUG FIXES
- Fix digest mismatch on Windows line endings
```

## Testing

- Write table-driven tests where appropriate
- Use golden files for CLI output testing
- Add acceptance tests for new CLI commands
- Mock external dependencies (Sigstore, network calls)

## Package Structure

```
pack/           # Core pack reading/validation
pack/builder/   # Pack creation
pack/merge/     # Pack merging
pack/verify/    # Sigstore verification
sign/           # Signing operations
errors/         # Typed error handling
cmd/epack/      # CLI implementation
```

## Questions?

Open an issue if you have questions about contributing or need help getting started.
