---
title: "Access Control Procedures (AC) — Kube-Policies (KP)"
control_family: "AC — Access Control"
controls: "AC-1, AC-2, AC-3, AC-5, AC-6, AC-17"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Access Control Procedures (AC) — Kube-Policies (KP)

These are the operational procedures that implement the KP Access Control policy
([policies/AC-policy.md](../policies/AC-policy.md)) for the **FIPS-199 Moderate**
Proof-of-Concept. They are the **how-to** companion to the AC-1 policy and the
code-grounded [IAM control narrative](../iam-control-narrative.md). They cover
RBAC management for the policy-manager and dashboard, account/role-binding
management, authenticator provisioning, and periodic access review. Part of the
[compliance evidence package](../README.md).

Kube-Policies is **not yet authorized** (no ATO). Steps below reflect the
**as-built** chart and binaries; where a step is not yet wired it is flagged
**(gap — tracked in POA&M)**. The management-plane OIDC + RBAC enforcement is
**config-gated** (`security.authentication.enabled`, default `false` in the chart);
production deployments **must** enable it.

## Annual review

These procedures are reviewed and updated at least **annually** (next scheduled
review **2027-06-01**) and whenever the RBAC manifests, the role model, the
authenticator provisioning path, or the set of interfaces materially changes. The
ISSO (TBD — assign before assessment) performs the review; the AO (TBD — assign
before assessment) re-approves as part of the AC posture.

## 1 RBAC management — policy-manager API (AC-2, AC-3, AC-6)

The management-plane authorization model is **OIDC group → role**
(`viewer`/`editor`/`admin`), enforced by a deny-by-default table
(`internal/policymanager/authz.go`).

### 1.1 Enabling enforcement (required for production)

1. Set `auth.enabled=true` and supply `auth.issuer`, `auth.jwksUrl`, and a
   non-empty `auth.audience` in the chart values. The chart **fails to render**
   if any is missing (`charts/kube-policies/templates/configmap.yaml`).
2. Confirm the policy-manager logged `policy-manager API authentication configured`
   with `oidc_enforced=true` (`cmd/policy-manager/main.go`). If the startup log
   instead carries the `SECURITY: OIDC authentication is DISABLED … served
   UNAUTHENTICATED` warning, the gate is **off** — treat as a deviation and do not
   run that posture outside development.

### 1.2 Granting a role to an IdP group

1. Add a `RoleBinding` under `security.rbac.role_bindings` mapping the IdP group(s)
   to one of `viewer`/`editor`/`admin` (`internal/config/config.go`, `RBACConfig`).
2. Optionally set `security.rbac.default_role` for authenticated principals with no
   matching binding; leave it empty to **deny mutations** by default.
3. Apply the chart. Config load validates every role name — an invalid name fails
   startup, so a typo cannot silently grant or withhold access.
4. Verify: a token whose groups match the binding can reach the role's routes; a
   token with no matching group and no `default_role` is denied **403** on every
   protected route.

### 1.3 Changing or revoking a role

Revoke access by removing the user from the IdP group (preferred — immediate at the
IdP) or by editing/removing the `RoleBinding` and re-applying. Lowering a role takes
effect on the next request because the effective role is recomputed per request
(`roleForPrincipal`). Record the change per §4.

## 2 RBAC management — dashboard (AC-5, AC-6)

The dashboard runs under its own ServiceAccount with a **narrow namespaced Role**
(read-only `get` on the two named Services; **no** CRD/Secret/TokenReview access)
(`charts/kube-policies/templates/dashboard-rbac.yaml`).

1. Do **not** broaden the dashboard Role; it intentionally cannot read CRDs or
   Secrets. New dashboard data needs **shall** be served through the policy-manager
   API, not by widening this Role.
2. The dashboard SA defaults `automountServiceAccountToken: false`; it does not call
   the apiserver at runtime. Leave it off.
3. The dashboard authenticates **operators** via OIDC + server-side sessions
   (IAM-WU-04/16) and forwards per-user identity to the policy-manager. Manage the
   dashboard's own `dashboard.auth` block per the IA procedures and the IAM
   narrative.
4. Keep the dashboard **read-only** (`ALLOW_WRITES` unset/false,
   `cmd/dashboard/config.go`) unless a reviewed, risk-accepted need exists; this is
   a blast-radius control, not the authorization boundary.

## 3 Authenticator provisioning (AC-2, AC-6; lifecycle in IA procedures)

Provisioning of the four authenticators is detailed in the IA procedures
([procedures/IA-procedures.md](IA-procedures.md)); the AC-relevant provisioning
steps are:

1. **OIDC operators (#1)** — provisioned at the IdP; access to KP is granted by
   adding the operator to the IdP group bound to a KP role (§1.2). Removing the
   group membership de-provisions KP access.
2. **mTLS client certs (#2)** — issued via cert-manager (IAM-WU-03/06); see the IA
   procedures for issuance/rotation.
3. **Projected SA tokens (#3)** — provisioned declaratively by the chart: the
   webhook and dashboard Deployments mount audience-bound projected
   `serviceAccountToken` volumes (`charts/kube-policies/templates/*-deployment.yaml`),
   and the policy-manager is told the expected webhook and dashboard SA subjects
   (`POLICY_MANAGER_INTERNAL_SUBJECT`, `POLICY_MANAGER_DECISIONS_READER_SUBJECT`).
   No manual token handling is required in `tokenreview` mode.
4. **Static internal token (#4)** — provisioned only in `mode=static`
   (non-cluster/demo); see the IA procedures for generation and rotation.

When a workload's SA subject changes, update the corresponding
`POLICY_MANAGER_*_SUBJECT` value so the TokenReview subject pin still matches, or the
decision-plane request is rejected.

## 4 Periodic access review (AC-6(7), AC-2)

At least **annually** (and on any role-model or RBAC-manifest change), the ISSO
(TBD — assign) shall:

1. Review every `security.rbac.role_bindings` entry against current operator need;
   remove stale group→role grants and confirm `default_role` is still appropriate.
2. Review the three ServiceAccount (Cluster)Roles in
   `charts/kube-policies/templates/rbac.yaml` and
   `charts/kube-policies/templates/dashboard-rbac.yaml` against least privilege;
   confirm no rule has been broadened beyond the CRD/status/lease/TokenReview/Service
   grants documented in the [IAM control narrative](../iam-control-narrative.md) §11.2.
3. Confirm the management-plane authN gate is **enabled** in every non-dev
   environment and that `ALLOW_WRITES` is off unless risk-accepted.
4. Record the review outcome and any remediation in the [POA&M](../poam.csv).

## 5 Records

- Role-binding grants/changes/revocations and periodic access reviews: recorded by
  the ISSO and tracked, with any risk acceptances, in the [POA&M](../poam.csv).
- RBAC-manifest changes: recorded in version control (PR review) and reflected in
  the [IAM control narrative](../iam-control-narrative.md).

## 6 References

- AC policy: [policies/AC-policy.md](../policies/AC-policy.md)
- IAM control narrative: [iam-control-narrative.md](../iam-control-narrative.md)
- IA procedures: [procedures/IA-procedures.md](IA-procedures.md)
- Authorization / config code: `internal/policymanager/authz.go`, `internal/policymanager/router.go`, `internal/config/config.go`, `cmd/policy-manager/main.go`
- Dashboard write kill-switch: `cmd/dashboard/config.go`
- RBAC manifests: `charts/kube-policies/templates/rbac.yaml`, `charts/kube-policies/templates/dashboard-rbac.yaml`
- Deployment SA-token wiring: `charts/kube-policies/templates/policy-manager-deployment.yaml`, `charts/kube-policies/templates/admission-webhook-deployment.yaml`, `charts/kube-policies/templates/dashboard-deployment.yaml`
- Control matrix / POA&M: [control-matrix.csv](../control-matrix.csv), [poam.csv](../poam.csv)
- Compliance index: [README](../README.md)
- NIST SP 800-53 Rev 5 (AC-2, AC-3, AC-5, AC-6, AC-6(7), AC-17); FedRAMP Moderate baseline.
