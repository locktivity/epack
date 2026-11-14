.PHONY: all build build-core build-conformance check test test-all test-race test-conformance fuzz lint lint-boundary clean install install-core govulncheck

# Every target runs as CI does: against the modules go.mod pins, not a go.work
# that points at local checkouts, and under go.mod's toolchain line, the Go
# release CI installs. golangci-lint panics on a Go release newer than the one
# it was built with. Set either variable in the environment to override.
export GOWORK ?= off
GO_TOOLCHAIN := $(shell sed -n 's/^toolchain \([^[:space:]]*\).*/\1/p' go.mod)
export GOTOOLCHAIN ?= $(GO_TOOLCHAIN)

# Default target builds the full version with components
all: build

# Everything CI checks that one machine can run, from a fresh clone.
check: lint lint-boundary build build-core build-conformance test-race test-conformance fuzz govulncheck

# Build full version (with components) - this is the default
build:
	go build -tags components -o epack ./cmd/epack

# Build core version (no components)
build-core:
	go build -o epack-core ./cmd/epack

# Build conformance test harness
build-conformance:
	go build -tags conformance -o epack-conformance ./cmd/epack-conformance

# Run tests for core build only
test:
	go test ./...

# Run tests for all build configurations
test-all:
	@echo "Testing core build..."
	go test ./...
	@echo ""
	@echo "Testing full build (components)..."
	go test -tags components ./...

# Run tests with race detector
test-race:
	go test -race ./...
	go test -race -tags components ./...

# Run tests for the conformance harness, which builds only with its tag
test-conformance:
	go test -race -tags conformance ./internal/componentconf/...

# Run fuzz tests (default 10s per target, override with FUZZTIME=1m)
FUZZTIME ?= 10s
fuzz:
	./scripts/fuzz.sh $(FUZZTIME)

# Lint with the golangci-lint version CI runs, built by go run under the
# toolchain above, so there is no install script and no binary to keep current
GOLANGCI_LINT_VERSION := v2.15.0
GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint:
	$(GOLANGCI_LINT) run ./...
	$(GOLANGCI_LINT) run --build-tags components ./...

# Known vulnerabilities reachable from either build, at the govulncheck
# version CI runs
GOVULNCHECK_VERSION := v1.8.0

govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) -tags components ./...

# Verify import boundary: core cmd package must not import internal packages directly
# Also verifies security-critical packages don't import internal/catalog
lint-boundary:
	@echo "Checking component import boundary..."
	@if grep -r 'epack/internal/collector' cmd/epack/cmd/*.go 2>/dev/null | grep -v '_test.go' | grep -v 'register_collector.go'; then \
		echo "ERROR: cmd/epack/cmd imports internal/collector directly"; \
		exit 1; \
	fi
	@if grep -r 'epack/internal/component' cmd/epack/cmd/*.go 2>/dev/null | grep -v '_test.go' | grep -v 'register_collector.go'; then \
		echo "ERROR: cmd/epack/cmd imports internal/component directly"; \
		exit 1; \
	fi
	@echo "Checking catalog isolation boundary..."
	@# SECURITY: internal/dispatch, internal/collector, and internal/component must NOT import internal/catalog
	@# Catalog is display-only; trust decisions come exclusively from lockfile
	@if grep -r 'epack/internal/catalog' internal/dispatch/*.go 2>/dev/null | grep -v '_test.go'; then \
		echo "ERROR: internal/dispatch imports internal/catalog (security boundary violation)"; \
		exit 1; \
	fi
	@if grep -r 'epack/internal/catalog' internal/collector/*.go 2>/dev/null | grep -v '_test.go'; then \
		echo "ERROR: internal/collector imports internal/catalog (security boundary violation)"; \
		exit 1; \
	fi
	@if grep -r 'epack/internal/catalog' internal/component/*.go 2>/dev/null | grep -v '_test.go'; then \
		echo "ERROR: internal/component imports internal/catalog (security boundary violation)"; \
		exit 1; \
	fi
	@echo "Import boundary OK"

# Clean build artifacts
clean:
	go clean ./...
	rm -f epack epack-core epack-conformance

# Install full version (components)
install:
	go install -tags components ./cmd/epack

# Install core version (as epack-core binary)
install-core:
	go build -o $(GOPATH)/bin/epack-core ./cmd/epack
