package componentsdk

import (
	"strings"
	"testing"
)

func TestConfigSchemaChecksTheConfigBeforeTheHandlerRuns(t *testing.T) {
	schema := []byte(`{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "required": ["host"],
	  "additionalProperties": false,
	  "properties": {"host": {"type": "string", "minLength": 1}, "port": {"type": "integer", "minimum": 1, "maximum": 65535}}}`)
	ran := false
	handler := func(ctx CollectorContext) error {
		ran = true
		return ctx.Emit([]CollectedArtifact{{Path: "artifacts/probe.json", Data: map[string]any{"ok": true}}})
	}
	run := func(schema []byte, config map[string]any) InProcessResult {
		ran = false
		return RunInProcess(CollectorSpec{Name: "probe", ConfigSchema: schema}, handler, InProcessOptions{Config: config, OutputDir: t.TempDir()})
	}

	bad := run(schema, map[string]any{"host": "example.com", "port": "https", "extra": true})
	switch {
	case ran:
		t.Error("the handler ran with a config that does not match the schema")
	case bad.ExitCode != CodeConfigInvalid.ExitCode() || bad.Failure == nil || bad.Failure.Code != CodeConfigInvalid:
		t.Errorf("run = exit %d failure %+v, want config_invalid", bad.ExitCode, bad.Failure)
	case !strings.Contains(bad.Failure.Message, "/port") || !strings.Contains(bad.Failure.Message, "the top level"):
		t.Errorf("failure message %q should list /port and the top level", bad.Failure.Message)
	case strings.Contains(bad.Failure.Message, "https"):
		t.Errorf("failure message %q should not quote a value", bad.Failure.Message)
	case !strings.Contains(bad.Stderr, "config /port"):
		t.Errorf("stderr should give the details: %q", bad.Stderr)
	}

	if res := run(schema, map[string]any{"host": "example.com", "port": 8443, "level": "audit"}); !ran || res.ExitCode != 0 {
		t.Errorf("a matching config with the SDK's level key: ran %v, exit %d, failure %+v", ran, res.ExitCode, res.Failure)
	}
	if res := run(schema, nil); ran || res.Failure == nil || !strings.Contains(res.Failure.Message, "the top level") {
		t.Errorf("a missing config lacks the required host: ran %v, failure %+v", ran, res.Failure)
	}
	if res := run([]byte(`{"type": 7}`), map[string]any{"anything": 1}); !ran || res.ExitCode != 0 || !strings.Contains(res.Stderr, "does not compile") {
		t.Errorf("a schema that does not compile should skip the check and warn: ran %v, exit %d, stderr %q", ran, res.ExitCode, res.Stderr)
	}
	if res := run(nil, map[string]any{"port": "https"}); !ran || res.ExitCode != 0 {
		t.Errorf("without a schema, the SDK should not check the config: ran %v, exit %d", ran, res.ExitCode)
	}
}
