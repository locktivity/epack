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
		// Emit minimal evidence
		data := map[string]any{
			"collected_at": time.Now().UTC().Format(time.RFC3339),
			"source":       ctx.Name(),
			"items":        []any{},
		}
		return ctx.Emit(data)
	})
}
