// Minimal tool fixture for SDK conformance testing.
// Build: go build -o epack-tool-sdk-fixture ./componentsdk/fixtures/tool
package main

import (
	"github.com/locktivity/epack/componentsdk"
)

func main() {
	componentsdk.RunTool(componentsdk.ToolSpec{
		Name:         "sdk-fixture",
		Version:      "1.0.0",
		Description:  "Minimal tool for SDK conformance testing",
		RequiresPack: false,
	}, func(ctx componentsdk.ToolContext) error {
		// Write a simple output
		result := map[string]any{
			"message": "SDK fixture executed successfully",
			"run_id":  ctx.RunID(),
		}
		return ctx.WriteOutput("result.json", result)
	})
}
