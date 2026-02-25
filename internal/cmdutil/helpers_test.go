package cmdutil

import (
	"testing"

	"github.com/locktivity/epack/internal/component/config"
)

func TestFilterConfigComponents(t *testing.T) {
	t.Run("filter collectors", func(t *testing.T) {
		cfg := &config.JobConfig{
			Collectors: map[string]config.CollectorConfig{
				"github": {Source: "owner/github@v1"},
				"deps":   {Source: "owner/deps@v1"},
			},
			Tools: map[string]config.ToolConfig{
				"ai": {Source: "owner/ai@v1"},
			},
		}

		result, err := FilterConfigComponents(cfg, []string{"github"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Collectors) != 1 {
			t.Errorf("expected 1 collector, got %d", len(result.Collectors))
		}
		if _, ok := result.Collectors["github"]; !ok {
			t.Error("github collector not in result")
		}
		if len(result.Tools) != 0 {
			t.Errorf("expected 0 tools, got %d", len(result.Tools))
		}
	})

	t.Run("filter tools", func(t *testing.T) {
		cfg := &config.JobConfig{
			Collectors: map[string]config.CollectorConfig{
				"github": {Source: "owner/github@v1"},
			},
			Tools: map[string]config.ToolConfig{
				"ai":     {Source: "owner/ai@v1"},
				"viewer": {Source: "owner/viewer@v1"},
			},
		}

		result, err := FilterConfigComponents(cfg, []string{"ai"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Tools) != 1 {
			t.Errorf("expected 1 tool, got %d", len(result.Tools))
		}
		if _, ok := result.Tools["ai"]; !ok {
			t.Error("ai tool not in result")
		}
	})

	t.Run("filter remotes", func(t *testing.T) {
		cfg := &config.JobConfig{
			Collectors: map[string]config.CollectorConfig{
				"github": {Source: "owner/github@v1"},
			},
			Remotes: map[string]config.RemoteConfig{
				"locktivity": {Source: "owner/remote@v1"},
				"other":      {Source: "owner/other@v1"},
			},
		}

		result, err := FilterConfigComponents(cfg, []string{"locktivity"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Remotes) != 1 {
			t.Errorf("expected 1 remote, got %d", len(result.Remotes))
		}
		if _, ok := result.Remotes["locktivity"]; !ok {
			t.Error("locktivity remote not in result")
		}
		if len(result.Collectors) != 0 {
			t.Errorf("expected 0 collectors, got %d", len(result.Collectors))
		}
	})

	t.Run("component not found", func(t *testing.T) {
		cfg := &config.JobConfig{
			Collectors: map[string]config.CollectorConfig{
				"github": {Source: "owner/github@v1"},
			},
		}

		_, err := FilterConfigComponents(cfg, []string{"nonexistent"})
		if err == nil {
			t.Fatal("expected error for nonexistent component")
		}
	})

	t.Run("mixed types", func(t *testing.T) {
		cfg := &config.JobConfig{
			Collectors: map[string]config.CollectorConfig{
				"github": {Source: "owner/github@v1"},
			},
			Tools: map[string]config.ToolConfig{
				"ai": {Source: "owner/ai@v1"},
			},
			Remotes: map[string]config.RemoteConfig{
				"locktivity": {Source: "owner/remote@v1"},
			},
		}

		result, err := FilterConfigComponents(cfg, []string{"github", "ai", "locktivity"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Collectors) != 1 {
			t.Errorf("expected 1 collector, got %d", len(result.Collectors))
		}
		if len(result.Tools) != 1 {
			t.Errorf("expected 1 tool, got %d", len(result.Tools))
		}
		if len(result.Remotes) != 1 {
			t.Errorf("expected 1 remote, got %d", len(result.Remotes))
		}
	})
}
