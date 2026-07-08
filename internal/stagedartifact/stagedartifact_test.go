package stagedartifact

import "testing"

func TestEntryValidate(t *testing.T) {
	tests := []struct {
		name     string
		entry    Entry
		wantFile string
		wantErr  bool
	}{
		{name: "data only", entry: Entry{HasData: true}, wantFile: ""},
		{name: "file with path", entry: Entry{File: "documents/policy.pdf", Path: "artifacts/documents/policy.pdf"}, wantFile: "documents/policy.pdf"},
		{name: "file and data are exclusive", entry: Entry{HasData: true, File: "a.pdf", Path: "artifacts/a.pdf"}, wantErr: true},
		{name: "file requires path", entry: Entry{File: "a.pdf"}, wantErr: true},
		{name: "file rejects absolute", entry: Entry{File: "/etc/passwd", Path: "artifacts/passwd"}, wantErr: true},
		{name: "file rejects traversal", entry: Entry{File: "../escape.pdf", Path: "artifacts/escape.pdf"}, wantErr: true},
		{name: "neither file nor data", entry: Entry{Path: "artifacts/x"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.entry.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got file %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantFile {
				t.Errorf("file = %q, want %q", got, tt.wantFile)
			}
		})
	}
}

func TestLocalPath(t *testing.T) {
	for _, p := range []string{"documents/policy.pdf", "policy.pdf"} {
		if err := LocalPath(p); err != nil {
			t.Errorf("LocalPath(%q) = %v, want nil", p, err)
		}
	}
	for _, p := range []string{"", "/abs.pdf", "../escape.pdf"} {
		if err := LocalPath(p); err == nil {
			t.Errorf("LocalPath(%q) = nil, want error", p)
		}
	}
}
