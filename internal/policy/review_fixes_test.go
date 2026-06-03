package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// These tests lock the fixes from the P10 adversarial review so the bypasses
// cannot regress.

// TestParameterDefaultFiresWithoutParameters locks the fail-open fix: a
// parameterized rule must still enforce its in-Rego default when the policy
// carries NO Parameters (input.parameters is always injected as at least {}).
func TestParameterDefaultFiresWithoutParameters(t *testing.T) {
	p := governanceBaselinePolicy()
	p.Parameters = nil // simulate a CR that drops the parameters block
	res := evalScoped(t, p, "", "v1", "Pod",
		`{"kind":"Pod","metadata":{"name":"p","namespace":"app","labels":{"app.kubernetes.io/name":"x"}},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`)
	assert.False(t, res.Allowed, "require-labels must still enforce its default set when Parameters is nil")
	assert.True(t, firedRuleIDs(res)["require-labels"])
}

// TestNetworkPolicyEmptyFromIsAllowAll locks the fix for an ingress rule with an
// explicit empty from:[] (semantically allow-all).
func TestNetworkPolicyEmptyFromIsAllowAll(t *testing.T) {
	res := evalScoped(t, networkBaselinePolicy(), "networking.k8s.io", "v1", "NetworkPolicy",
		`{"kind":"NetworkPolicy","metadata":{"name":"n","namespace":"app"},"spec":{"podSelector":{},"ingress":[{"from":[]}],"policyTypes":["Ingress"]}}`)
	assert.False(t, res.Allowed, "empty from:[] is allow-all and must be denied")
	assert.True(t, firedRuleIDs(res)["deny-overly-broad-netpol"])
}

// TestConfigMapBinaryDataScanned locks the fix for sensitive keys hidden in
// binaryData rather than data.
func TestConfigMapBinaryDataScanned(t *testing.T) {
	res := evalScoped(t, secretsBaselinePolicy(), "", "v1", "ConfigMap",
		`{"kind":"ConfigMap","metadata":{"name":"cm","namespace":"app"},"binaryData":{"db_password":"aGk="}}`)
	assert.False(t, res.Allowed, "sensitive key in binaryData must be flagged")
	assert.True(t, firedRuleIDs(res)["flag-configmap-sensitive"])
}

// TestRegistryPrefixBoundary locks the fix for prefix-without-boundary spoofing:
// a registry that merely starts with an allowed prefix must NOT pass.
func TestRegistryPrefixBoundary(t *testing.T) {
	// Default allowlist is ghcr.io/jibbscript/.
	spoof := evalScoped(t, imageProvenancePolicy(), "", "v1", "Pod",
		`{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"ghcr.io/jibbscript.evil.com/x@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}}`)
	assert.False(t, spoof.Allowed, "registry starting-with but not bounded by the allowed prefix must be denied")
	assert.True(t, firedRuleIDs(spoof)["allowed-registries"])

	legit := evalScoped(t, imageProvenancePolicy(), "", "v1", "Pod",
		`{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"ghcr.io/jibbscript/app@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}}`)
	assert.True(t, legit.Allowed, "legitimately-prefixed image must be allowed; violations=%+v", legit.Violations)
}
