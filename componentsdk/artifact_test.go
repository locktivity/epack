package componentsdk

import (
	"testing"

	"github.com/locktivity/epack/internal/stagedartifact"
)

func TestArtifactConstructors(t *testing.T) {
	jsonArt := JSONArtifact("artifacts/doc.json", map[string]any{"k": "v"}, ArtifactMeta{
		Schema:      "evidencepack/soc2-report@v1",
		DisplayName: "Acme SOC 2 2025",
		Description: "SOC 2 Type II report",
		Controls:    []string{"CC6.1"},
	})
	if jsonArt.Data == nil || jsonArt.File != "" {
		t.Errorf("JSONArtifact should set Data only: %+v", jsonArt)
	}
	if jsonArt.Path != "artifacts/doc.json" || jsonArt.Schema != "evidencepack/soc2-report@v1" ||
		jsonArt.DisplayName != "Acme SOC 2 2025" || jsonArt.Description != "SOC 2 Type II report" ||
		len(jsonArt.Controls) != 1 {
		t.Errorf("JSONArtifact metadata not applied: %+v", jsonArt)
	}

	fileArt := FileArtifact("artifacts/documents/policy.pdf", "documents/policy.pdf",
		ArtifactMeta{DisplayName: "Security policy"})
	if fileArt.File == "" || fileArt.Data != nil {
		t.Errorf("FileArtifact should set File only: %+v", fileArt)
	}
	if fileArt.Path != "artifacts/documents/policy.pdf" || fileArt.DisplayName != "Security policy" {
		t.Errorf("FileArtifact metadata not applied: %+v", fileArt)
	}

	for _, a := range []CollectedArtifact{jsonArt, fileArt} {
		if _, err := (stagedartifact.Entry{HasData: a.Data != nil, File: a.File, Path: a.Path}).Validate(); err != nil {
			t.Errorf("constructed artifact failed validation: %v", err)
		}
	}
}
