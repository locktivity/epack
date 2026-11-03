package collectortest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Variant is the clean scenario rewritten for another deployment of the
// vendor, such as an AWS partition other than aws, an Azure national cloud,
// or a vendor's regional domain. The kit applies Replace to the clean
// scenario's canned URLs, headers, bodies, and request bodies, and to the
// suite's config and env. It runs the rewritten scenario and checks that
// each data artifact equals the clean run's with the same rewrite. A value
// that does not follow the rewrite, such as an ARN prefix the collector
// hard-codes, is a violation. A request the rewritten scenario has no
// response for, such as one to a hard-coded host, is also a violation.
type Variant struct {
	// Name labels the variant in reports, such as "aws-us-gov".
	Name string

	// Replace lists old, new pairs, such as "arn:aws:", "arn:aws-us-gov:",
	// "us-east-1", "us-gov-west-1". The pairs are applied together, as
	// strings.NewReplacer applies them. Each old string must be specific
	// enough to change only what differs between the deployments. Replace
	// works on the text as the scenario holds it. A value that a body holds
	// encoded, such as the URL-encoded policy documents IAM sends, needs its
	// encoded form listed too, such as "arn%3Aaws%3A". Replace cannot reach
	// a value encoded in base64.
	Replace []string
}

// checkVariants runs each of Suite.Variants and compares its output with
// the clean run's, rewritten the same way.
func (k *kit) checkVariants() {
	clean := k.suite.Scenarios[0]
	for _, v := range k.suite.Variants {
		label := v.Name
		r := strings.NewReplacer(v.Replace...)
		scenario := rewriteScenario(clean, r)
		scenario.Config, _ = rewriteAny(k.configFor(clean), r).(map[string]any)
		scenario.Env = map[string]string{}
		for key, value := range overlay(k.suite.Env, clean.Env) {
			scenario.Env[key] = r.Replace(value)
		}
		res, n := k.runOnce("variants", label, scenario, nil)
		for _, miss := range n.unmatched() {
			k.violate("variants", label, "%s. The variant rewrites every canned URL, so the collector built this URL some other way, such as from a hard-coded host", miss)
		}
		if res.ExitCode != 0 {
			k.violate("variants", label, "the run failed with exit %d and %s, but the clean run succeeded", res.ExitCode, failureLabel(res))
			continue
		}
		want := map[string]map[string]any{}
		for path, a := range artifactsByPath(k.baseline.Artifacts) {
			doc, ok := decodeJSON(string(a.Data))
			if !ok {
				continue
			}
			raw, err := json.Marshal(sortLists(rewriteAny(doc, r)))
			if err != nil {
				continue
			}
			if flat, err := flatten(raw); err == nil {
				want[r.Replace(path)] = flat
			}
		}
		for _, d := range diffSorted(want, sortedArtifacts(res.Artifacts), k.ignore) {
			k.violate("variants", label, "%s. The first value is the clean run's value with the variant's rewrite applied. "+
				"A value must change with the deployment. Read prefixes, partitions, and hosts from the vendor's answers or config, and do not hard-code them", d)
		}
	}
}

// rewriteScenario applies r to the URLs, header values, bodies, and request
// bodies of s's canned responses. A CBOR body is left alone, since a rewrite
// can change the lengths its encoding records.
func rewriteScenario(s Scenario, r *strings.Replacer) Scenario {
	out := s
	out.Name = s.Name
	out.Responses = make([]Response, len(s.Responses))
	for i, resp := range s.Responses {
		c := resp
		c.URL = r.Replace(resp.URL)
		c.RequestBody = r.Replace(resp.RequestBody)
		if resp.decoded || !isCBOR(resp.Header.Get("Content-Type")) {
			c.Body = r.Replace(resp.Body)
		}
		if resp.Header != nil {
			c.Header = http.Header{}
			for key, values := range resp.Header {
				for _, v := range values {
					c.Header.Add(key, r.Replace(v))
				}
			}
		}
		out.Responses[i] = c
	}
	return out
}

// rewriteAny applies r to every string in a decoded JSON value, keys
// included.
func rewriteAny(v any, r *strings.Replacer) any {
	switch n := v.(type) {
	case string:
		return r.Replace(n)
	case map[string]any:
		out := make(map[string]any, len(n))
		for key, child := range n {
			out[r.Replace(key)] = rewriteAny(child, r)
		}
		return out
	case []any:
		out := make([]any, len(n))
		for i, child := range n {
			out[i] = rewriteAny(child, r)
		}
		return out
	}
	return v
}

// checkVariantSpecs returns an error for a variant the kit cannot run.
func checkVariantSpecs(variants []Variant) error {
	for _, v := range variants {
		switch {
		case v.Name == "":
			return fmt.Errorf("a variant in Suite.Variants has no Name")
		case len(v.Replace) == 0 || len(v.Replace)%2 != 0:
			return fmt.Errorf("variant %q needs Replace as old, new pairs", v.Name)
		}
		for i := 0; i < len(v.Replace); i += 2 {
			if v.Replace[i] == "" {
				return fmt.Errorf("variant %q replaces an empty string", v.Name)
			}
		}
	}
	return nil
}
