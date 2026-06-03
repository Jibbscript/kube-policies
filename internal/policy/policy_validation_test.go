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

// TestRestrictedCapabilities_DeniesDangerousBuiltins proves the sandbox: a rule
// whose Rego body references a denied builtin (http.send and friends) must FAIL
// at the compile/validation gate — i.e. the builtin is not in the capability set
// the engine compiles against — rather than being executed (SSRF/exfil). The
// failure surfaces as a compile error ("does not compile") because the restricted
// capabilities make the builtin unknown to the compiler.
func TestRestrictedCapabilities_DeniesDangerousBuiltins(t *testing.T) {
	denied := []struct {
		name string
		body string
	}{
		{
			name: "http.send",
			body: `package kube_policies
import rego.v1
default evaluate := {"allowed": true}
evaluate := {"allowed": false, "message": "x"} if {
	resp := http.send({"method": "get", "url": "http://169.254.169.254/"})
	resp.status_code == 200
}`,
		},
		{
			name: "net.lookup_ip_addr",
			body: `package kube_policies
import rego.v1
default evaluate := {"allowed": true}
evaluate := {"allowed": false, "message": "x"} if {
	net.lookup_ip_addr("metadata.internal")
}`,
		},
		{
			name: "opa.runtime",
			body: `package kube_policies
import rego.v1
default evaluate := {"allowed": true}
evaluate := {"allowed": false, "message": "x"} if {
	opa.runtime().env.PATH != ""
}`,
		},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRuleRego("sandbox_"+tc.name, tc.body)
			require.Errorf(t, err, "rule using %s must be rejected, not executed", tc.name)
			assert.Containsf(t, err.Error(), "does not compile",
				"%s should fail to compile under the restricted capability set; got: %v", tc.name, err)
		})
	}
}

// TestRestrictedCapabilities_AllowsLegitimateRules guards against an over-broad
// strip: ordinary deny logic over input (object/parameters) and the shared
// library must still compile and evaluate unaffected.
func TestRestrictedCapabilities_AllowsLegitimateRules(t *testing.T) {
	body := `package kube_policies
import rego.v1
import data.kube_policies.lib as lib
default evaluate := {"allowed": true}
evaluate := {"allowed": false, "message": "priv", "path": "p"} if {
	some e in lib.containers_with_paths
	e.container.securityContext.privileged == true
}`
	require.NoError(t, ValidateRuleRego("legit_rule", body),
		"a normal library-backed deny rule must compile under the restricted capabilities")
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
