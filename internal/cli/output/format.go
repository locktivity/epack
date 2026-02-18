package output

import (
	"encoding/json"
	"fmt"
)

// DigestMaxLen is the default max length for truncated digests.
// Shows algorithm prefix plus first few chars: "sha256:abc123..."
const DigestMaxLen = 19

// FormatDigest shortens a digest string for display using the default length.
func FormatDigest(digest string) string {
	return TruncateDigest(digest, DigestMaxLen)
}

// TruncateDigest shortens a digest string for display with custom length.
// Keeps the algorithm prefix and first few characters.
func TruncateDigest(digest string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = DigestMaxLen
	}
	if len(digest) > maxLen {
		return digest[:maxLen] + "..."
	}
	return digest
}

// FormatBytes formats a byte count as a human-readable string (KB, MB, GB).
func FormatBytes(n int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1f GB", float64(n)/GB)
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/MB)
	case n >= KB:
		return fmt.Sprintf("%.1f KB", float64(n)/KB)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// FormatBytesFromJSON formats a json.Number byte count as human-readable.
// Returns empty string if n is nil.
func FormatBytesFromJSON(n *json.Number) string {
	if n == nil {
		return ""
	}
	size, err := n.Int64()
	if err != nil {
		return n.String()
	}
	return FormatBytes(size)
}
