package policy

import (
	"fmt"
	"regexp"
)

// PolicyBundleVersion is the SemVer version of the bundled policy library
// (POL-WU-26). Bump it whenever a bundled rule is added, removed, or its
// behavior changes, and record the change in CHANGELOG-policies.md. The bundle
// version is distinct from any individual Policy.Version.
const PolicyBundleVersion = "1.0.0"

// semverRe is a pragmatic SemVer 2.0.0 matcher: major.minor.patch with optional
// -prerelease and +build metadata.
var semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$`)

// ValidateSemVer returns an error if v is not a valid SemVer string.
func ValidateSemVer(v string) error {
	if !semverRe.MatchString(v) {
		return fmt.Errorf("%q is not a valid SemVer version", v)
	}
	return nil
}

// ruleBundleVersions records the bundle version in which each shipped rule was
// introduced (POL-WU-26). It is the source for CHANGELOG-policies.md and the
// per-rule version/stable-ID assertions: every bundled rule MUST appear here
// (TestEveryBundledRuleHasAVersion) and every key MUST be a real bundled rule
// (no orphans). Rule IDs are stable identifiers and are unique across the bundle.
var ruleBundleVersions = map[string]string{
	// security-baseline (rebased onto the shared podspec library in 1.0.0)
	"no-privileged-containers":  "1.0.0",
	"no-host-path-volumes":      "1.0.0",
	"no-latest-image-tag":       "1.0.0",
	"required-security-context": "1.0.0",

	// image-provenance
	"allowed-registries":   "1.0.0",
	"require-image-digest": "1.0.0",

	// pss-baseline
	"deny-host-namespaces":     "1.0.0",
	"restrict-capabilities":    "1.0.0",
	"deny-host-port":           "1.0.0",
	"seccomp-not-unconfined":   "1.0.0",
	"deny-unsafe-sysctls":      "1.0.0",
	"deny-apparmor-unconfined": "1.0.0",

	// pss-restricted
	"require-no-privilege-escalation": "1.0.0",
	"require-drop-all-capabilities":   "1.0.0",
	"require-readonly-rootfs":         "1.0.0",
	"require-run-as-nonroot":          "1.0.0",
	"restrict-volume-types":           "1.0.0",

	// nsa-hardening
	"require-resource-limits":          "1.0.0",
	"require-automount-token-disabled": "1.0.0",

	// governance-baseline
	"require-labels":         "1.0.0",
	"deny-default-namespace": "1.0.0",

	// rbac-baseline
	"deny-wildcard-rbac":         "1.0.0",
	"deny-dangerous-verbs":       "1.0.0",
	"deny-cluster-admin-binding": "1.0.0",
	"deny-broad-subject-binding": "1.0.0",

	// secrets-baseline
	"deny-secret-env":          "1.0.0",
	"flag-configmap-sensitive": "1.0.0",

	// network-baseline
	"deny-overly-broad-netpol":        "1.0.0",
	"ingress-require-tls-no-wildcard": "1.0.0",

	// mutating-hardening
	"harden-pod-securitycontext": "1.0.0",
}

// RuleVersion returns the bundle version a rule was introduced in, and whether
// the rule is recorded.
func RuleVersion(ruleID string) (string, bool) {
	v, ok := ruleBundleVersions[ruleID]
	return v, ok
}
