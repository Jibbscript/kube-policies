package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// TestExamplePoliciesCompile guarantees every illustrative Policy CR under
// examples/policies/ honors the engine contract and compiles WITH the shared
// library (POL-WU-01/24). Examples document what users should copy; a broken or
// drifted example (e.g. one that forgets `import data.kube_policies.lib`, or that
// a doc-generation step reindented incorrectly) would mislead operators, so it
// fails the build here.
func TestExamplePoliciesCompile(t *testing.T) {
	type exampleRule struct {
		Name string `json:"name"`
		Rego string `json:"rego"`
	}
	type examplePolicy struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Rules []exampleRule `json:"rules"`
		} `json:"spec"`
	}

	dir := filepath.Join("..", "..", "examples", "policies")
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, matches, "expected example policies under %s", dir)

	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			require.NoError(t, err)

			var p examplePolicy
			require.NoErrorf(t, yaml.Unmarshal(raw, &p), "%s is not a valid Policy CR", path)
			require.NotEmptyf(t, p.Spec.Rules, "%s has no spec.rules", path)

			for _, r := range p.Spec.Rules {
				name := p.Metadata.Name + "_" + r.Name
				assert.NoErrorf(t, ValidateRuleRego(name, r.Rego),
					"example rule %q in %s must compile and honor the engine contract", r.Name, path)
			}
		})
	}
}
