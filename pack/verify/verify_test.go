package verify

import (
	"regexp"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.offline {
		t.Error("default config should not be offline")
	}
	if cfg.tlogThreshold != 1 {
		t.Errorf("tlogThreshold = %d, want 1", cfg.tlogThreshold)
	}
	if cfg.tsaThreshold != 0 {
		t.Errorf("tsaThreshold = %d, want 0", cfg.tsaThreshold)
	}
}

func TestApplyOptions(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want func(*config) bool
	}{
		{
			name: "no options",
			opts: nil,
			want: func(c *config) bool {
				return !c.offline && c.tlogThreshold == 1
			},
		},
		{
			name: "with issuer",
			opts: []Option{WithIssuer("https://accounts.google.com")},
			want: func(c *config) bool {
				return c.issuer == "https://accounts.google.com"
			},
		},
		{
			name: "with subject",
			opts: []Option{WithSubject("user@example.com")},
			want: func(c *config) bool {
				return c.subject == "user@example.com"
			},
		},
		{
			name: "with offline",
			opts: []Option{WithOffline()},
			want: func(c *config) bool {
				return c.offline
			},
		},
		{
			name: "with issuer regexp",
			opts: []Option{WithIssuerRegexp(regexp.MustCompile(`https://.*\.google\.com`))},
			want: func(c *config) bool {
				return c.issuerRegexp != nil && c.issuerRegexp.MatchString("https://accounts.google.com")
			},
		},
		{
			name: "with subject regexp",
			opts: []Option{WithSubjectRegexp(regexp.MustCompile(`.*@example\.com`))},
			want: func(c *config) bool {
				return c.subjectRegexp != nil && c.subjectRegexp.MatchString("user@example.com")
			},
		},
		{
			name: "with tlog threshold",
			opts: []Option{WithTransparencyLogThreshold(2)},
			want: func(c *config) bool {
				return c.tlogThreshold == 2
			},
		},
		{
			name: "with tsa threshold",
			opts: []Option{WithTimestampAuthorityThreshold(1)},
			want: func(c *config) bool {
				return c.tsaThreshold == 1
			},
		},
		{
			name: "multiple options",
			opts: []Option{
				WithIssuer("https://accounts.google.com"),
				WithSubject("user@example.com"),
				WithOffline(),
			},
			want: func(c *config) bool {
				return c.issuer == "https://accounts.google.com" &&
					c.subject == "user@example.com" &&
					c.offline
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := applyOptions(tt.opts)
			if !tt.want(cfg) {
				t.Errorf("config does not match expected state")
			}
		})
	}
}

func TestResult(t *testing.T) {
	// Test that Result struct can be properly constructed
	result := &Result{
		Verified: true,
		Identity: &Identity{
			Issuer:  "https://accounts.google.com",
			Subject: "user@example.com",
		},
		Statement: &Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://slsa.dev/provenance/v1",
			Subjects: []Subject{
				{
					Name:   "artifact.tar.gz",
					Digest: map[string]string{"sha256": "abc123"},
				},
			},
		},
	}

	if !result.Verified {
		t.Error("result.Verified should be true")
	}
	if result.Identity.Issuer != "https://accounts.google.com" {
		t.Errorf("Identity.Issuer = %q, want %q", result.Identity.Issuer, "https://accounts.google.com")
	}
	if result.Identity.Subject != "user@example.com" {
		t.Errorf("Identity.Subject = %q, want %q", result.Identity.Subject, "user@example.com")
	}
	if result.Statement.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("Statement.Type = %q, want %q", result.Statement.Type, "https://in-toto.io/Statement/v1")
	}
	if len(result.Statement.Subjects) != 1 {
		t.Errorf("len(Statement.Subjects) = %d, want 1", len(result.Statement.Subjects))
	}
}
