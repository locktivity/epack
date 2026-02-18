// Package componentsdk provides a framework for building epack components
// (collectors, tools, remote adapters, and utilities) that are conformant
// with the epack component specification.
//
// The SDK eliminates protocol boilerplate and ensures conformance by construction:
//   - Automatic --capabilities handling
//   - Automatic result.json generation with correct timestamps
//   - Automatic exit code mapping
//   - Pack reading with size limits enforced
//   - Output path validation (no traversal, relative paths only)
//
// # Building a Tool
//
//	func main() {
//	    componentsdk.RunTool(componentsdk.ToolSpec{
//	        Name:         "my-analyzer",
//	        Version:      "1.0.0",
//	        Description:  "Analyzes evidence packs",
//	        RequiresPack: true,
//	    }, func(ctx componentsdk.ToolContext) error {
//	        pack := ctx.Pack()
//	        // ... analyze pack ...
//	        return ctx.WriteOutput("analysis.json", result)
//	    })
//	}
//
// # Building a Collector
//
//	func main() {
//	    componentsdk.RunCollector(componentsdk.CollectorSpec{
//	        Name:    "my-service",
//	        Version: "1.0.0",
//	    }, func(ctx componentsdk.CollectorContext) error {
//	        data := fetchFromAPI(ctx.Config(), ctx.Secret("API_TOKEN"))
//	        return ctx.Emit(data)
//	    })
//	}
//
// # Conformance
//
// Components built with this SDK automatically pass conformance tests for:
//   - Binary naming (C-001, C-002, C-003)
//   - Capabilities output (TOOL-001, COL-002, REM-001, etc.)
//   - Result format (TOOL-030 through TOOL-052)
//   - Exit codes (C-020, C-021, C-022)
//   - Timestamp formatting (TOOL-050, TOOL-051)
//   - Output path validation (TOOL-040, TOOL-041, TOOL-042)
package componentsdk
