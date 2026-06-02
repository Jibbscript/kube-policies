package policy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRuleRego(t *testing.T) {
	cases := []struct {
		name    string
		rego    string
		wantErr string // substring; empty means expect success
	}{
		{
			name: "valid rule with default",
			rego: `package kube_policies
import rego.v1
default evaluate := {"allowed": true}
evaluate := {"allowed": false, "message": "no", "path": "x"} if { input.object.spec.bad }`,
		},
		{
			name: "valid rule importing the shared library",
			rego: `package kube_policies
import rego.v1
import data.kube_policies.lib as lib
default evaluate := {"allowed": true}
evaluate := {"allowed": false, "message": "priv", "path": "p"} if {
	some e in lib.containers_with_paths
	e.container.securityContext.privileged == true
}`,
		},
		{
			name:    "non-compiling rego",
			rego:    `package kube_policies` + "\n" + `import rego.v1` + "\n" + `evaluate := {"allowed": false`, /* unterminated */
			wantErr: "does not compile",
		},
		{
			name: "omits evaluate (always-allow)",
			rego: `package kube_policies
import rego.v1
some_other_rule := 1`,
			wantErr: "must define data.kube_policies.evaluate",
		},
		{
			name: "evaluate missing boolean allowed",
			rego: `package kube_policies
import rego.v1
evaluate := {"message": "x"}`,
			wantErr: "boolean \"allowed\"",
		},
		{
			name:    "empty body",
			rego:    "   ",
			wantErr: "empty rego body",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRuleRego("test_"+tc.name, tc.rego)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Containsf(t, err.Error(), tc.wantErr, "got: %v", err)
		})
	}
}

// TestAllBundledRulesValidate is a strong invariant: every rule the engine
// bundles must pass the same compile/contract gate customer policies face. This
// guards the shared-library wiring (a bundled rule that imports the lib must
// compile WITH the lib) and the engine contract for the whole library.
func TestAllBundledRulesValidate(t *testing.T) {
	eng := newDefaultEngine(t)
	for _, p := range eng.ListPolicies() {
		require.NoErrorf(t, ValidatePolicy(p), "bundled policy %q failed validation", p.ID)
	}
}

// TestValidatePolicy_ReportsOffendingRule verifies the rule-scoped error wrap.
func TestValidatePolicy_ReportsOffendingRule(t *testing.T) {
	p := &Policy{
		ID: "p",
		Rules: []Rule{
			{ID: "good", Rego: `package kube_policies
import rego.v1
default evaluate := {"allowed": true}`},
			{ID: "bad", Rego: `package kube_policies
import rego.v1
nope := 1`},
		},
	}
	err := ValidatePolicy(p)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), `rule "bad"`), "got: %v", err)
}
