package execsafe

import (
	"testing"
)

func TestValidateSecretName(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		// Valid secrets - operators can pass any credential they want
		{"valid API key", "GITHUB_TOKEN", false},
		{"valid custom secret", "MY_API_KEY", false},
		{"valid AWS key", "AWS_ACCESS_KEY_ID", false},
		{"valid openai", "OPENAI_API_KEY", false},
		{"valid PATH", "PATH", false},   // Operators can pass PATH if they want
		{"valid SHELL", "SHELL", false}, // Operators can pass SHELL if they want
		{"valid HOME", "HOME", false},   // Operators can pass HOME if they want
		{"valid PYTHONPATH", "PYTHONPATH", false},
		{"valid NODE_OPTIONS", "NODE_OPTIONS", false},

		// Denied prefixes - these would compromise epack's own execution
		{"denied EPACK_ prefix", "EPACK_CUSTOM", true},
		{"denied EPACK_RUN_ID", "EPACK_RUN_ID", true},
		{"denied LD_ prefix", "LD_PRELOAD", true},
		{"denied LD_LIBRARY_PATH", "LD_LIBRARY_PATH", true},
		{"denied LD_CUSTOM", "LD_CUSTOM", true},
		{"denied DYLD_ prefix", "DYLD_INSERT_LIBRARIES", true},
		{"denied DYLD_CUSTOM", "DYLD_CUSTOM", true},
		{"denied _ prefix", "_INTERNAL", true},

		// Edge cases - similar prefixes that are NOT denied
		{"allowed EPACKAGE", "EPACKAGE", false},   // Doesn't start with EPACK_
		{"allowed LOADING", "LOADING", false},     // Doesn't start with LD_
		{"allowed LDAP_HOST", "LDAP_HOST", false}, // Starts with LD but not LD_
		{"allowed DYLAN", "DYLAN", false},         // Starts with DY but not DYLD_

		// Empty name
		{"empty name", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretName(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSecretName(%q) error = %v, wantErr %v", tt.secret, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSecretNames(t *testing.T) {
	tests := []struct {
		name    string
		secrets []string
		wantErr bool
	}{
		{
			name:    "all valid",
			secrets: []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY"},
			wantErr: false,
		},
		{
			name:    "one invalid - EPACK prefix",
			secrets: []string{"GITHUB_TOKEN", "EPACK_CUSTOM", "OPENAI_API_KEY"},
			wantErr: true,
		},
		{
			name:    "multiple invalid",
			secrets: []string{"LD_PRELOAD", "EPACK_CUSTOM", "DYLD_INSERT_LIBRARIES"},
			wantErr: true,
		},
		{
			name:    "empty list",
			secrets: []string{},
			wantErr: false,
		},
		{
			name:    "nil list",
			secrets: nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretNames(tt.secrets)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSecretNames(%v) error = %v, wantErr %v", tt.secrets, err, tt.wantErr)
			}
		})
	}
}

func TestFilterValidSecrets(t *testing.T) {
	tests := []struct {
		name     string
		secrets  []string
		expected []string
	}{
		{
			name:     "all valid",
			secrets:  []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "PATH"},
			expected: []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "PATH"},
		},
		{
			name:     "some invalid",
			secrets:  []string{"GITHUB_TOKEN", "LD_PRELOAD", "OPENAI_API_KEY", "EPACK_CUSTOM"},
			expected: []string{"GITHUB_TOKEN", "OPENAI_API_KEY"},
		},
		{
			name:     "all invalid",
			secrets:  []string{"LD_PRELOAD", "EPACK_CUSTOM", "DYLD_INSERT_LIBRARIES"},
			expected: nil,
		},
		{
			name:     "empty",
			secrets:  []string{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterValidSecrets(tt.secrets)
			if len(got) != len(tt.expected) {
				t.Errorf("FilterValidSecrets(%v) = %v, want %v", tt.secrets, got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("FilterValidSecrets(%v)[%d] = %v, want %v", tt.secrets, i, got[i], tt.expected[i])
				}
			}
		})
	}
}
