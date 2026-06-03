package policy

import (
	"fmt"
	"sort"
)

// EnforcementProfiles maps a profile name to the EXACT set of bundled policy IDs
// it enables (POL-WU-23). Selecting one or more profiles makes the engine's
// enabled set precisely the union of their lists — nothing else — so an operator
// chooses a curated enforcement level instead of a flat all-or-nothing bundle.
//
// Each profile is a tested set: TestProfilesEnableExactlyTheirPolicies asserts
// that selecting a profile enables exactly these IDs, and every ID here must be
// a real bundled policy (TestProfilePolicyIDsExist).
var EnforcementProfiles = map[string][]string{
	// PSS Baseline: the original security-baseline plus the PSS-Baseline pack.
	"pss-baseline": {
		"security-baseline",
		"pss-baseline",
	},
	// PSS Restricted: baseline plus the restricted pack.
	"pss-restricted": {
		"security-baseline",
		"pss-baseline",
		"pss-restricted",
	},
	// PSS Restricted + auto-hardening mutation (defaults missing fields).
	"pss-restricted-mutating": {
		"security-baseline",
		"pss-baseline",
		"pss-restricted",
		"mutating-hardening",
	},
	// NSA/CISA + NIST 800-190: restricted plus resource/automount hardening and
	// image provenance (registry allowlist + digest pinning).
	"nsa": {
		"security-baseline",
		"pss-baseline",
		"pss-restricted",
		"nsa-hardening",
		"image-provenance",
	},
	// CIS: the full Kubernetes-benchmark-aligned set across pods, RBAC, secrets,
	// network, and governance.
	"cis": {
		"security-baseline",
		"pss-baseline",
		"pss-restricted",
		"nsa-hardening",
		"rbac-baseline",
		"secrets-baseline",
		"network-baseline",
		"governance-baseline",
	},
}

// ProfileNames returns the known profile names in sorted order.
func ProfileNames() []string {
	names := make([]string, 0, len(EnforcementProfiles))
	for name := range EnforcementProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ProfilePolicyIDs returns the policy IDs a profile enables, and whether the
// profile is known.
func ProfilePolicyIDs(name string) ([]string, bool) {
	ids, ok := EnforcementProfiles[name]
	if !ok {
		return nil, false
	}
	out := make([]string, len(ids))
	copy(out, ids)
	return out, true
}

// applyProfiles sets each bundled policy's Enabled flag to whether it belongs to
// the union of the named profiles (POL-WU-23). An unknown profile is an error.
// After this runs, the enabled set is EXACTLY that union, so selecting
// "pss-baseline" enables only the baseline policies and selecting nothing leaves
// the engine's defaults untouched (this is only called when profiles are set).
//
// CONSTRUCTION-ONLY: this mutates Policy.Enabled without holding e.mutex and is
// safe only because NewEngine calls it before the engine is published to any
// goroutine. Do not call it on a live engine (it would race Evaluate's
// RLock-guarded reads of Policy.Enabled); add locking first if a live
// reconfigure path is ever introduced.
func (e *Engine) applyProfiles(profiles []string) error {
	want := make(map[string]bool)
	for _, name := range profiles {
		ids, ok := EnforcementProfiles[name]
		if !ok {
			return fmt.Errorf("unknown enforcement profile %q (known: %v)", name, ProfileNames())
		}
		for _, id := range ids {
			want[id] = true
		}
	}
	for id, p := range e.policies {
		p.Enabled = want[id]
	}
	return nil
}

// EnabledPolicyIDs returns the sorted IDs of all currently-enabled policies.
// Used by profile tests and operational inspection.
func (e *Engine) EnabledPolicyIDs() []string {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	out := make([]string, 0, len(e.policies))
	for id, p := range e.policies {
		if p.Enabled {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
