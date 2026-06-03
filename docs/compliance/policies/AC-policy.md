---
title: "Access Control Policy (AC) — Kube-Policies (KP)"
control_family: "AC — Access Control"
controls: "AC-1, AC-2, AC-3, AC-5, AC-6, AC-17"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Access Control Policy (AC) — Kube-Policies (KP)

This policy addresses the NIST SP 800-53 Rev 5 **Access Control (AC)** family for
the Kube-Policies (KP) system, categorized **FIPS-199 Moderate** under the FedRAMP
**Moderate** baseline. It establishes the **AC-1** policy artifact and states the
access-control requirements that the KP code and Helm chart implement. The
operational steps live in the companion procedures
([procedures/AC-procedures.md](../procedures/AC-procedures.md)); the code-grounded
implementation view is the [IAM control narrative](../iam-control-narrative.md);
the inter-service authenticator lifecycle is the IA policy
([policies/IA-policy.md](IA-policy.md)). Part of the
[compliance evidence package](../README.md).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment
readiness**; it is **not yet authorized** (no ATO). This policy claims **only what
the shipped code and chart implement** and marks everything else **Planned** or, for
config-gated enforcement, **Partial**. Per-control status is tracked in the
[control matrix](../control-matrix.csv); open weaknesses are in the
[POA&M](../poam.csv).

> **Scope honesty note.** The KP management-plane access enforcement (OIDC + RBAC)
> is **config-gated**: it is active only when
> `security.authentication.enabled == true` (`internal/config/config.go`,
> `AuthConfig`) and a verifier is constructed
> (`internal/policymanager/router.go`, `NewAPIRouter`). The **chart default is
> `auth.enabled: false`** (`charts/kube-policies/values.yaml`); a default-values
> install therefore serves the management API **unauthenticated** — a dev-only
> posture and a **tracked gap**, not a claimed control. The **decision plane**
> (`/api/v1/decisions/*`) is authenticated **unconditionally** by service tokens.
> Human access to the **cluster** is governed by **Kubernetes RBAC / the cluster
> IdP**, which are **inherited / out-of-boundary** (`../CRM.md`).

## Annual review

This policy is reviewed and updated at least **annually** (next scheduled review
**2027-06-01**) and whenever the authorization model, the RBAC manifests, the set
of interfaces, the threat environment, or the applicable standards materially
change. Reviews are performed by the ISSO (TBD — assign before assessment) and
re-approved by the Authorizing Official (TBD — assign before assessment),
consistent with AC-1.

## 1 Purpose and scope

The purpose of this policy is to ensure that every identity — human operator or
KP service workload — is granted access to KP resources only after it is
authenticated and only to the extent its role requires, following **least
privilege** and **deny-by-default**.

It applies to:

- All KP authorization-boundary components in the `kube-policies-system` namespace
  (`AST-WH` admission webhook, `AST-PM` policy-manager, `AST-DB`/`AST-SPA`
  dashboard), per `../system-facts.md`.
- The application-layer authorization model (viewer/editor/admin) on the
  policy-manager API.
- The Kubernetes ServiceAccounts and RBAC objects that the chart provisions for
  the three planes.
- All personnel filling the System Owner, ISSO, AO, and Independent Assessor
  roles, plus any contributor who changes the authorization code, the RBAC chart
  templates, or this artifact.

Named ATO roles are **not yet staffed**; this policy refers to them by title with
"TBD — assign before assessment".

## 2 AC-1 — Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate an access-control policy
and the procedures needed to implement it; shall designate an official to manage
them; and shall review and update both on a defined frequency. This document is
that policy; the operational procedures are
[procedures/AC-procedures.md](../procedures/AC-procedures.md).

### 2.2 AC-1(a) — Scope and recipients

This policy applies to the scope in §1. It is disseminated to the System Owner,
ISSO, AO, Independent Assessor, and all repository contributors by being maintained
in version control under `docs/compliance/policies/` and referenced from the SSP
([ssp/SSP.md](../ssp/SSP.md), AC family) and the index ([README](../README.md)).

### 2.3 AC-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and
update this policy and its procedures, with the **System Owner (TBD — assign before
assessment)** accountable for adequacy and resourcing. The **AO (TBD — assign before
assessment)** approves the access-control posture as part of the authorization
decision.

### 2.4 AC-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This AC policy (AC-1) | ISSO | At least annually | Significant change; new/changed standard; assessor finding |
| AC procedures ([procedures/AC-procedures.md](../procedures/AC-procedures.md)) | ISSO | At least annually | RBAC manifest change; new role; new interface; provisioning-tooling change |
| IAM control narrative ([iam-control-narrative.md](../iam-control-narrative.md)) | ISSO | At least annually | Authorization-model or authenticator change |

## 3 Access-control requirements

### 3.1 AC-3 — Deny-by-default access enforcement

The policy-manager management API **shall** authorize every protected route from
an **explicit, deny-by-default** table: a route not listed, or a principal whose
role is below the route's requirement, **shall** be denied (`403`). No wildcard
allow is permitted. This is implemented by the `requiredRoles` table and
`RBACMiddleware` (`internal/policymanager/authz.go`); it is mounted when
authentication is enabled (`internal/policymanager/router.go`). The decision plane
(`/api/v1/decisions/*`) **shall** require a valid service token unconditionally
(`internal/policymanager/decisions_handler.go`).

### 3.2 AC-2 — Roles, not stored accounts

KP **shall not** maintain a local human-user account store; interactive identity
**shall** be federated from the cluster/external OIDC IdP (`../CRM.md`). The roles
KP defines (`viewer`/`editor`/`admin`) **shall** be derived from IdP groups via
`RoleBindings` (`internal/config/config.go`).

### 3.3 The viewer / editor / admin model

| Role | Authorized actions |
|---|---|
| **viewer** | Read management resources (policies, bundles, exceptions, compliance reports/frameworks) and run read-only evaluation RPCs (test/validate/evaluate). |
| **editor** | viewer **plus** create/update/delete of policies, bundles, and exceptions. |
| **admin** | editor **plus** privileged operations (policy deploy, compliance-report generation). |

A principal's effective role is the highest role across matching `RoleBindings`,
or the configured `DefaultRole` when none match; an empty `DefaultRole` denies
mutations. Role names are validated at config load
(`internal/config/config.go`) so a typo cannot silently grant access.

### 3.4 `ALLOW_WRITES` — defense-in-depth write kill-switch (not authZ)

The dashboard BFF ships **read-only by default**: write verbs
(`POST`/`PUT`/`PATCH`/`DELETE`) through its reverse proxy are blocked (`403`)
unless the operator sets `ALLOW_WRITES=true` (`cmd/dashboard/config.go`,
`AllowWrites`, default false). `ALLOW_WRITES` is a **defense-in-depth blast-radius
control**, **not** a substitute for authorization: it does not identify or
authenticate anyone, and it **shall not** be relied on as the primary access
control. The primary access control on the management API is the OIDC + RBAC layer
of §3.1. Enabling `ALLOW_WRITES` without the management-plane authN gate enabled is
a **deviation** to be risk-accepted and tracked in the [POA&M](../poam.csv).

### 3.5 AC-5 — Separation of duties

KP **shall** run its three planes under **three distinct ServiceAccounts** bound to
**three distinct (Cluster)Roles** so no plane inherits another's privileges
(`charts/kube-policies/templates/rbac.yaml`,
`charts/kube-policies/templates/dashboard-rbac.yaml`). The application roles
**shall** separate read, mutate, and privileged operations.

### 3.6 AC-6 — Least privilege

Every granted permission — Kubernetes RBAC rule and application role — **shall** be
the minimum required for the function. The webhook/policy-manager ClusterRoles
grant only the CRD verbs and `/status` patches the reconcilers need; the
TokenReview `create` grant is on the policy-manager **only** and only in
`tokenreview` mode; the dashboard Role is read-only on two named Services
(`charts/kube-policies/templates/rbac.yaml`,
`charts/kube-policies/templates/dashboard-rbac.yaml`). New permissions **shall** be
justified in review against this principle.

### 3.7 AC-17 — Remote access

KP **shall** expose no general-purpose remote-access service. Remotely reachable
planes **shall** be served over TLS 1.3 (`internal/config/tls.go`); the management
plane **shall** additionally require OIDC bearer authN (when enabled) and **may**
require client-cert mTLS (IAM-WU-03).

## 4 Roles and responsibilities (summary)

| Role | Holder | AC responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for the access-control posture and resourcing; approves this policy. |
| ISSO | TBD — assign before assessment | Designated official; maintains this policy, the procedures, and the IAM narrative; performs periodic access review; tracks POA&M. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the access-control posture as part of the authorization decision. |
| Independent Assessor | TBD — assign before assessment | Independently assesses AC controls during the SAR. |
| Cluster Operator (customer) | TBD (Customer) | Operates cluster RBAC / IdP; manages OIDC group membership that drives KP roles; applies the chart RBAC. |

## 5 Compliance, exceptions, and enforcement

- Deviations require documented risk acceptance by the System Owner (within
  delegated authority) or the AO and are recorded in the [POA&M](../poam.csv).
- Running the management plane with `security.authentication.enabled=false`
  outside a development environment, or enabling `ALLOW_WRITES` without the authN
  gate, are deviations to be risk-accepted and tracked, not silent defaults.
- Nothing in this artifact constitutes an authorization to operate.

## 6 References

- AC procedures: [procedures/AC-procedures.md](../procedures/AC-procedures.md)
- IAM control narrative: [iam-control-narrative.md](../iam-control-narrative.md)
- IA policy / procedures: [policies/IA-policy.md](IA-policy.md), [procedures/IA-procedures.md](../procedures/IA-procedures.md)
- Authorization code: `internal/policymanager/authz.go`, `internal/policymanager/router.go`, `internal/policymanager/auth_middleware.go`, `internal/config/config.go`
- Dashboard write kill-switch: `cmd/dashboard/config.go` (`ALLOW_WRITES`)
- RBAC manifests: `charts/kube-policies/templates/rbac.yaml`, `charts/kube-policies/templates/dashboard-rbac.yaml`
- Control matrix / POA&M / SSP / CRM: [control-matrix.csv](../control-matrix.csv), [poam.csv](../poam.csv), [ssp/SSP.md](../ssp/SSP.md), [CRM.md](../CRM.md)
- Compliance index: [README](../README.md)
- NIST SP 800-53 Rev 5 (AC-1, AC-2, AC-3, AC-5, AC-6, AC-17); FedRAMP Moderate baseline; FIPS-199.
