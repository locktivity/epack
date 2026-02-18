//go:build conformance

// Package componentconf implements conformance testing for epack components
// (collectors, tools, and remote adapters).
package componentconf

import "github.com/locktivity/epack/internal/componenttypes"

// RequirementLevel indicates the RFC 2119 level of a requirement.
type RequirementLevel string

const (
	LevelMust   RequirementLevel = "MUST"
	LevelShould RequirementLevel = "SHOULD"
	LevelMay    RequirementLevel = "MAY"
)

// Requirement defines a single conformance requirement.
type Requirement struct {
	ID          string                        // Unique identifier (e.g., "COL-001")
	Level       RequirementLevel              // MUST, SHOULD, MAY
	Description string                        // Human-readable description
	Types       []componenttypes.ComponentKind // Which component types this applies to
}

// TestStatus indicates the result of a conformance test.
type TestStatus string

const (
	StatusPass TestStatus = "pass"
	StatusFail TestStatus = "fail"
	StatusSkip TestStatus = "skip"
)

// TestResult represents the result of testing a single requirement.
type TestResult struct {
	ID      string           `json:"id"`
	Level   RequirementLevel `json:"level"`
	Status  TestStatus       `json:"status"`
	Message string           `json:"message,omitempty"`
	Reason  string           `json:"reason,omitempty"` // Why skipped
}

// Report contains the full conformance test results.
type Report struct {
	Component    string                       `json:"component"`
	Type         componenttypes.ComponentKind `json:"type"`
	Level        string                       `json:"conformance_level"` // minimal, standard, full
	Results      []TestResult           `json:"results"`
	Summary      ReportSummary          `json:"summary"`
	Capabilities map[string]interface{} `json:"capabilities,omitempty"`
}

// ReportSummary provides aggregate counts.
type ReportSummary struct {
	Must   LevelSummary `json:"must"`
	Should LevelSummary `json:"should"`
	May    LevelSummary `json:"may"`
}

// LevelSummary provides pass/fail/skip counts for a requirement level.
type LevelSummary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// increment increments the appropriate counter based on test status.
func (s *LevelSummary) increment(status TestStatus) {
	switch status {
	case StatusPass:
		s.Pass++
	case StatusFail:
		s.Fail++
	case StatusSkip:
		s.Skip++
	}
}

// summaryForLevel returns a pointer to the LevelSummary for the given requirement level.
func (r *ReportSummary) summaryForLevel(level RequirementLevel) *LevelSummary {
	switch level {
	case LevelMust:
		return &r.Must
	case LevelShould:
		return &r.Should
	case LevelMay:
		return &r.May
	default:
		return nil
	}
}

// ComputeLevel returns the achieved conformance level based on results.
func (r *Report) ComputeLevel() string {
	// Minimal: all MUST pass
	// Standard: all MUST and SHOULD pass
	// Full: all MUST, SHOULD, and MAY pass
	if r.Summary.Must.Fail > 0 {
		return "none"
	}
	if r.Summary.Should.Fail > 0 {
		return "minimal"
	}
	if r.Summary.May.Fail > 0 {
		return "standard"
	}
	return "full"
}
