#!/usr/bin/env bash
# Run all fuzz tests for a specified duration
# Usage: ./scripts/fuzz.sh [duration]
# Default duration is 10s per target

set -e

FUZZTIME="${1:-10s}"

echo "Running fuzz tests (${FUZZTIME} per target)..."

# Find all packages with fuzz tests
for file in $(find . -name '*_fuzz_test.go' -not -path './vendor/*'); do
    pkg=$(dirname "$file")

    # List all Fuzz functions in the package
    fuzz_funcs=$(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true)

    for func in $fuzz_funcs; do
        echo "Fuzzing $pkg $func..."
        # Use anchored regex to match exact function name (avoids prefix matching)
        # Set timeout to 2 minutes (higher than fuzztime) to allow clean exit
        go test -fuzz="^${func}\$" -fuzztime="$FUZZTIME" -timeout=2m "$pkg"
    done
done

echo "All fuzz tests completed."
