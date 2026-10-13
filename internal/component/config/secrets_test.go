package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safeyaml"
)

func TestSecretListAcceptsNamesAndOptionalEntries(t *testing.T) {
	cfg, err := Parse([]byte(`
stream: vendor/prod
collectors:
  aws:
    source: locktivity/epack-collector-aws@^0.5
    secrets:
      - AWS_WEB_IDENTITY_TOKEN_FILE
      - name: AWS_PROFILE
        optional: true
      - name: AWS_REGION
`))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	secrets := cfg.Collectors["aws"].Secrets
	if got := strings.Join(secrets.Names(), ","); got != "AWS_WEB_IDENTITY_TOKEN_FILE,AWS_PROFILE,AWS_REGION" {
		t.Fatalf("Names() = %s", got)
	}
	if secrets[0].Optional || !secrets[1].Optional || secrets[2].Optional {
		t.Fatalf("optional flags = %+v, want only AWS_PROFILE optional", secrets)
	}
}

func TestSecretListRefusesOtherShapes(t *testing.T) {
	for name, entry := range map[string]string{
		"unknown key":   `{name: AWS_PROFILE, required: false}`,
		"missing name":  `{optional: true}`,
		"duplicate key": "{name: A, name: B}",
		"reserved name": `{name: EPACK_SECRET, optional: true}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte("stream: vendor/prod\ncollectors:\n  aws:\n    source: locktivity/epack-collector-aws@^0.5\n    secrets:\n      - " + entry + "\n"))
			if err == nil {
				t.Fatalf("expected an error for %s", name)
			}
		})
	}
}

func TestSecretRefRoundTrips(t *testing.T) {
	list := SecretList{{Name: "GITHUB_TOKEN"}, {Name: "AWS_PROFILE", Optional: true}}

	out, err := safeyaml.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "- GITHUB_TOKEN\n- name: AWS_PROFILE\n  optional: true\n" {
		t.Fatalf("yaml = %q", out)
	}
	var back SecretList
	if err := safeyaml.Unmarshal(out, limits.ConfigFile, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 || back[0] != list[0] || back[1] != list[1] {
		t.Fatalf("yaml round trip = %+v", back)
	}

	js, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if string(js) != `["GITHUB_TOKEN",{"name":"AWS_PROFILE","optional":true}]` {
		t.Fatalf("json = %s", js)
	}
	var backJSON SecretList
	if err := json.Unmarshal(js, &backJSON); err != nil {
		t.Fatal(err)
	}
	if len(backJSON) != 2 || backJSON[1] != list[1] {
		t.Fatalf("json round trip = %+v", backJSON)
	}
	if err := json.Unmarshal([]byte(`[{"name":"AWS_PROFILE","required":false}]`), &backJSON); err == nil {
		t.Fatal("expected JSON to refuse a key other than name and optional")
	}
}
