# Enforcement Profiles

`kube-policies` ships a curated, tested rule library. Rather than a flat
all-or-nothing bundle, operators select an **enforcement profile** that activates
exactly one curated set of bundled policies (POL-WU-23). This lets you adopt a
known security posture (e.g. Pod Security Standards "restricted") and ratchet up
deliberately.

## Selecting a profile

Set `policy.profiles` in the webhook config (or the Helm chart `policy.profiles`
value):

```yaml
policy:
  failure_mode: fail-closed
  profiles:
    - pss-restricted
```

When `policy.profiles` is non-empty, the engine enables **exactly** the union of
the selected profiles' policies and disables everything else. When it is empty,
the engine keeps its default-enabled set (`security-baseline` only) so existing
deployments are unchanged.

An unknown profile name fails the webhook at startup (fail-closed on
misconfiguration).

## Profiles

| Profile | Enables | Use for |
|---|---|---|
| `pss-baseline` | `security-baseline`, `pss-baseline` | Block the most dangerous pod configs (host namespaces, dangerous capabilities, hostPort, Unconfined seccomp/AppArmor, unsafe sysctls). |
| `pss-restricted` | + `pss-restricted` | PSS Restricted: no privilege escalation, drop ALL caps, read-only rootfs, run-as-non-root, restricted volume types. |
| `pss-restricted-mutating` | `pss-restricted` set + `mutating-hardening` | Same as restricted, but auto-defaults missing securityContext fields via RFC6902 mutation before validation. |
| `nsa` | `pss-restricted` set + `nsa-hardening` + `image-provenance` | Adds resource requests/limits, service-account-token hardening, registry allowlist + image-digest pinning. |
| `cis` | full set: pods + `rbac-baseline` + `secrets-baseline` + `network-baseline` + `governance-baseline` | CIS Kubernetes Benchmark-aligned coverage across pods, RBAC, secrets, network, and governance. |

The authoritative profile→policy mapping lives in
`policy.EnforcementProfiles` (`internal/policy/profiles.go`) and is test-locked
(`TestProfilesEnableExactlyTheirPolicies`).

## Webhook coverage — selecting a profile is necessary but NOT sufficient

> **Important.** The shipped Helm chart and kustomize base register the admission
> webhook for **`pods` only** (`apiGroups: [""], resources: ["pods"]`). Selecting
> a profile enables the *rules* in the engine, but a rule only fires for objects
> the webhook actually intercepts. Two consequences:
>
> 1. **Workload controllers are not intercepted by default.** A privileged
>    `Deployment`/`DaemonSet`/`StatefulSet`/`Job`/`CronJob` is *not* evaluated at
>    controller-admission time; enforcement happens when the controller-spawned
>    **Pod** is admitted (the shared library still traverses init/ephemeral
>    containers on that Pod). To reject non-compliant workloads at apply time,
>    add the `apps`/`batch` workload-controller kinds to
>    `admissionWebhook.webhook.rules`.
> 2. **The RBAC, Secrets, and Network packs are inert until you widen coverage.**
>    The `rbac-baseline`, `secrets-baseline`, and `network-baseline` rules can
>    never fire unless you add `roles`/`clusterroles`/`rolebindings`/
>    `clusterrolebindings` (`rbac.authorization.k8s.io`), `configmaps`,
>    `networkpolicies`/`ingresses` (`networking.k8s.io`) to
>    `admissionWebhook.webhook.rules`. Selecting the `cis` profile alone does
>    **not** enforce them.
>
> Coverage is intentionally narrow by default so the fail-closed validating
> webhook's blast radius is not silently widened. Widen it deliberately, kind by
> kind, as you adopt each pack. See `charts/kube-policies/values.yaml` and
> `docs/compliance/cis-k8s-800-190-mapping.md` (POA&M POAM-POL-013).

## Per-rule control mappings

Each rule's control coverage (CIS / PSS / NSA / NIST) is documented in
`docs/policy-control-matrix.md` and the machine-checkable
`internal/policy/control_matrix.yaml`. The full rule catalog with allow/deny
examples is in `docs/policy-library.md`.
