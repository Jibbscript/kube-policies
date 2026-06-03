# Policy Bundle Changelog

This changelog tracks the bundled policy library shipped in `internal/policy`
(the rules the admission engine enforces). It is **separate** from the product
release changelog. The current bundle version is exposed as
`policy.PolicyBundleVersion` and validated as SemVer in CI
(`internal/policy/bundle_version_test`-style assertions in `profiles_version_test.go`).

Versioning policy (POL-WU-26):

- **MAJOR** — a rule is removed, or an existing rule's deny surface is widened in
  a way that can reject previously-admitted objects (breaking for operators).
- **MINOR** — a new rule or enforcement profile is added (opt-in; no change to
  the default-enabled set).
- **PATCH** — a message/path/metadata fix or a non-behavioral refactor.

Every shipped rule carries a stable ID and an introduced-in version recorded in
`ruleBundleVersions` (`internal/policy/bundle_version.go`); a test fails if any
shipped rule lacks a version or any recorded rule is no longer shipped.

## 1.0.0 — P10 Policy Library Completeness

First versioned bundle. Closes the workload-controller enforcement bypass and
ships a tested, profiled, control-mapped library.

### Engine

- Shared Rego pod-spec extraction library (`data.kube_policies.lib`,
  `internal/policy/rego/podspec.rego`) compiled alongside **every** rule; rules
  now evaluate the effective pod spec across Deployment/ReplicaSet/DaemonSet/
  StatefulSet/Job/CronJob templates, `initContainers`, and `ephemeralContainers`.
- Per-rule **kind routing** (`Rule.TargetKinds`): a rule is only evaluated
  against the Kubernetes kinds it targets, so pod rules never fire (or error and
  fail-close) on RBAC/Network/Secret objects, and vice versa.
- Per-policy **parameters** exposed to rules at `input.parameters`.
- Enforcement **profiles** (`policy.EnforcementProfiles`): `pss-baseline`,
  `pss-restricted`, `pss-restricted-mutating`, `nsa`, `cis`, selected via
  `policy.profiles` config.
- Admission-time **compile/contract gate** for customer Policy CRDs
  (`policy.ValidateRuleRego`): rejects non-compiling Rego and rules that omit
  `data.kube_policies.evaluate`; compiles WITH the shared library.

### Rules introduced (all 1.0.0)

| Policy | Rules |
|---|---|
| `security-baseline` (default-on) | no-privileged-containers, no-host-path-volumes, no-latest-image-tag, required-security-context — rebased onto the shared library |
| `image-provenance` (opt-in) | allowed-registries (parameterized), require-image-digest |
| `pss-baseline` (opt-in) | deny-host-namespaces, restrict-capabilities, deny-host-port, seccomp-not-unconfined, deny-unsafe-sysctls, deny-apparmor-unconfined |
| `pss-restricted` (opt-in) | require-no-privilege-escalation, require-drop-all-capabilities, require-readonly-rootfs, require-run-as-nonroot, restrict-volume-types |
| `nsa-hardening` (opt-in) | require-resource-limits, require-automount-token-disabled |
| `governance-baseline` (opt-in) | require-labels (parameterized), deny-default-namespace |
| `rbac-baseline` (opt-in) | deny-wildcard-rbac, deny-dangerous-verbs, deny-cluster-admin-binding, deny-broad-subject-binding |
| `secrets-baseline` (opt-in) | deny-secret-env, flag-configmap-sensitive |
| `network-baseline` (opt-in) | deny-overly-broad-netpol, ingress-require-tls-no-wildcard |
| `mutating-hardening` (opt-in) | harden-pod-securitycontext (RFC6902 defaulting) |

All packs except `security-baseline` ship **disabled by default** and are
activated by selecting an enforcement profile, so existing deployments are not
broken on upgrade.

See `docs/policy-library.md` (catalog) and `docs/policy-control-matrix.md`
(control traceability) for the full per-rule reference.
