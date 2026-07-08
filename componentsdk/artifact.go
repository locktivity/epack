package componentsdk

// ArtifactMeta carries optional manifest metadata for an artifact.
type ArtifactMeta struct {
	// Schema is the semantic schema type (e.g., "evidencepack/soc2-report@v1").
	Schema string
	// DisplayName is a human-readable name shown by epack inspect/list.
	DisplayName string
	// Description is a one-line description of the artifact.
	Description string
	// Controls lists the control IDs this artifact supports.
	Controls []string
}

// JSONArtifact builds a JSON data artifact at packPath.
func JSONArtifact(packPath string, data any, meta ArtifactMeta) CollectedArtifact {
	return CollectedArtifact{
		Data:        data,
		Path:        packPath,
		Schema:      meta.Schema,
		DisplayName: meta.DisplayName,
		Description: meta.Description,
		Controls:    meta.Controls,
	}
}

// FileArtifact builds a staged-file artifact at packPath.
func FileArtifact(packPath, stagedFile string, meta ArtifactMeta) CollectedArtifact {
	return CollectedArtifact{
		File:        stagedFile,
		Path:        packPath,
		Schema:      meta.Schema,
		DisplayName: meta.DisplayName,
		Description: meta.Description,
		Controls:    meta.Controls,
	}
}
