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
        # Capture output to check for real failures vs timeout
        set +e
        output=$(go test -fuzz="^${func}\$" -fuzztime="$FUZZTIME" -timeout=2m "$pkg" 2>&1)
        exit_code=$?
        set -e

        echo "$output"

        # Exit code 1 with "context deadline exceeded" is expected when fuzztime ends
        # Only fail if there's an actual test failure (not just timeout)
        if [ $exit_code -ne 0 ]; then
            if echo "$output" | grep -q "context deadline exceeded" && \
               ! echo "$output" | grep -q "FAIL.*\[" && \
               ! echo "$output" | grep -q "panic:"; then
                echo "  (fuzztime limit reached - OK)"
            else
                echo "FAIL: $pkg $func"
                exit 1
            fi
        fi
    done
done

echo "All fuzz tests completed."
