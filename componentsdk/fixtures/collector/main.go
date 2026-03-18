// Minimal collector fixture for SDK conformance testing.
// Build: go build -o epack-collector-sdk-fixture ./componentsdk/fixtures/collector
package main

import (
	"time"

	"github.com/locktivity/epack/componentsdk"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "sdk-fixture",
		Version:     "1.0.0",
		Description: "Minimal collector for SDK conformance testing",
	}, func(ctx componentsdk.CollectorContext) error {
		// Demonstrate progress reporting
		ctx.Status("Starting collection...")

		// Simulate collecting multiple items with progress
		items := []any{}
		for i := 1; i <= 3; i++ {
			ctx.Progress(int64(i), 3, "Collecting items")
			items = append(items, map[string]any{"id": i})
		}

		ctx.Status("Finalizing...")

		// Emit evidence
		data := map[string]any{
			"collected_at": time.Now().UTC().Format(time.RFC3339),
			"source":       ctx.Name(),
			"items":        items,
		}
		return ctx.Emit([]componentsdk.CollectedArtifact{{Data: data}})
	})
}
