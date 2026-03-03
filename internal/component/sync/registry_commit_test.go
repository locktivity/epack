package sync

import "testing"

func TestNormalizeCommitSHA(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "valid lowercase full sha",
			in:   "0123456789abcdef0123456789abcdef01234567",
			want: "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "valid uppercase short sha",
			in:   "ABCDEF1",
			want: "abcdef1",
		},
		{
			name: "branch name is rejected",
			in:   "main",
			want: "",
		},
		{
			name: "empty is rejected",
			in:   "",
			want: "",
		},
		{
			name: "non-hex is rejected",
			in:   "zzzzzzz",
			want: "",
		},
		{
			name: "too short is rejected",
			in:   "abc123",
			want: "",
		},
		{
			name: "too long is rejected",
			in:   "0123456789abcdef0123456789abcdef012345678",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeCommitSHA(tt.in)
			if got != tt.want {
				t.Errorf("normalizeCommitSHA(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
