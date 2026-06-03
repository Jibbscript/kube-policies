package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// TestProfilesEnableExactlyTheirPolicies proves POL-WU-23: selecting a profile
// makes the engine's enabled set exactly that profile's policy list.
func TestProfilesEnableExactlyTheirPolicies(t *testing.T) {
	for _, name := range ProfileNames() {
		t.Run(name, func(t *testing.T) {
			eng, err := NewEngine(&config.PolicyConfig{FailureMode: "fail-closed", Profiles: []string{name}}, zap.NewNop())
			require.NoError(t, err)
			want, ok := ProfilePolicyIDs(name)
			require.True(t, ok)
			assert.ElementsMatch(t, want, eng.EnabledPolicyIDs(),
				"profile %q must enable exactly its policy set", name)
		})
	}
}

// TestProfileBaselineVsRestricted spot-checks that baseline does NOT pull in the
// restricted pack and restricted DOES.
func TestProfileBaselineVsRestricted(t *testing.T) {
	base, err := NewEngine(&config.PolicyConfig{Profiles: []string{"pss-baseline"}}, zap.NewNop())
	require.NoError(t, err)
	assert.NotContains(t, base.EnabledPolicyIDs(), "pss-restricted")
	assert.Contains(t, base.EnabledPolicyIDs(), "pss-baseline")

	restricted, err := NewEngine(&config.PolicyConfig{Profiles: []string{"pss-restricted"}}, zap.NewNop())
	require.NoError(t, err)
	assert.Contains(t, restricted.EnabledPolicyIDs(), "pss-restricted")
}

// TestNoProfileLeavesDefaults proves that with no profile configured the engine
// keeps its default-enabled set (security-baseline only) — existing deployments
// are unchanged.
func TestNoProfileLeavesDefaults(t *testing.T) {
	eng, err := NewEngine(&config.PolicyConfig{}, zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, []string{"security-baseline"}, eng.EnabledPolicyIDs())
}

func TestUnknownProfileRejected(t *testing.T) {
	_, err := NewEngine(&config.PolicyConfig{Profiles: []string{"does-not-exist"}}, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown enforcement profile")
}

// TestProfilePolicyIDsExist proves every policy ID referenced by a profile is a
// real bundled policy — guards against typos that would silently enable nothing.
func TestProfilePolicyIDsExist(t *testing.T) {
	eng := newDefaultEngine(t)
	known := make(map[string]bool)
	for _, p := range eng.ListPolicies() {
		known[p.ID] = true
	}
	for name, ids := range EnforcementProfiles {
		for _, id := range ids {
			assert.Truef(t, known[id], "profile %q references unknown policy %q", name, id)
		}
	}
}

// --- POL-WU-26 bundle versioning ---

func TestValidateSemVer(t *testing.T) {
	assert.NoError(t, ValidateSemVer("1.0.0"))
	assert.NoError(t, ValidateSemVer("2.3.4-rc.1"))
	assert.NoError(t, ValidateSemVer(PolicyBundleVersion))
	assert.Error(t, ValidateSemVer("1.0"))
	assert.Error(t, ValidateSemVer("v1.0.0"))
	assert.Error(t, ValidateSemVer("latest"))
}

// TestEveryBundledRuleHasAVersion proves POL-WU-26: every shipped rule carries a
// stable ID and a recorded SemVer bundle version, and there are no orphan
// version entries for rules that no longer ship.
func TestEveryBundledRuleHasAVersion(t *testing.T) {
	eng := newDefaultEngine(t)

	shipped := make(map[string]bool)
	for _, p := range eng.ListPolicies() {
		// Each bundled policy must itself carry a SemVer version.
		assert.NoErrorf(t, ValidateSemVer(p.Version), "policy %q has non-SemVer version %q", p.ID, p.Version)
		for _, r := range p.Rules {
			require.NotEmptyf(t, r.ID, "policy %q has a rule with an empty (unstable) ID", p.ID)
			assert.Falsef(t, shipped[r.ID], "duplicate rule ID %q across the bundle", r.ID)
			shipped[r.ID] = true

			v, ok := RuleVersion(r.ID)
			assert.Truef(t, ok, "rule %q has no recorded bundle version", r.ID)
			assert.NoErrorf(t, ValidateSemVer(v), "rule %q version %q is not SemVer", r.ID, v)
		}
	}

	// No orphan entries: every recorded rule must still ship.
	for id := range ruleBundleVersions {
		assert.Truef(t, shipped[id], "ruleBundleVersions has orphan entry %q (rule no longer shipped)", id)
	}
}
