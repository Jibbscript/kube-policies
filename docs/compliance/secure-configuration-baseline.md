---
title: "Secure Configuration Baseline (CM-2 / CM-6) — Kube-Policies (KP)"
control_family: "CM — Configuration Management"
version: "0.2.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Secure Configuration Baseline — Kube-Policies (KP)

This document is the **CM-2 (Baseline Configuration)** and **CM-6 (Configuration
Settings)** secure configuration baseline for the Kube-Policies system (KP),
categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP
**Moderate** baseline). It enumerates, per component, the **required hardened
settings** and cites the **controlling Helm value path or rendered manifest
field** that establishes each one. Component names, asset IDs, ports, and trust
zones are used verbatim from the [system facts sheet](system-facts.md).

Kube-Policies is a Proof-of-Concept being driven to assessment readiness. This
baseline is **honest about gaps**: where the current chart already enforces a
setting, the controlling field is cited and the setting is marked
**Enforced (current)**. Where the chart does **not** yet enforce a required
setting, it is marked **Target (phase Pn)** and cross-referenced to the
remediating phase and POA&M item. Per-control status is tracked in the
[control matrix](control-matrix.csv); open weaknesses in the
[POA&M](poam.csv). Remediation phases (P0–P12) are defined in
`plans/remediation-roadmap.md`.

**Scope.** The configuration items (CIs) under this baseline are: the
admission-webhook (`AST-WH`), policy-manager (`AST-PM`), dashboard BFF
(`AST-DB`, with embedded SPA `AST-SPA`), and the Helm chart
(`AST-CHART`, `charts/kube-policies`) that renders them — including shared
ConfigMap, RBAC, TLS Secret, and Service objects. The embedded OPA evaluator
(`AST-OPA`) and the CRDs (`AST-CRD-POL`, `AST-CRD-EXC`) inherit the runtime
configuration of their host services.

**Authoritative sources.** Settings are sourced from the chart
(`charts/kube-policies/values.yaml`, `charts/kube-policies/templates/*.yaml`)
and from the runtime configuration validator (`internal/config/config.go`),
which fails closed on out-of-range values. Where a setting is enforced by the
**binary** rather than a Helm value, that is stated explicitly (it is a
configuration *default* the chart does not currently expose for override).

**Annual review.** This baseline is reviewed and updated at least **annually**
(next review **2027-05-29**) and whenever a significant change occurs to the
system, the chart, the container images, the threat environment, or the
applicable standards. Baseline changes are governed by the change-control
process in the forthcoming **Configuration Management Plan** (see
[§7 CM Plan linkage](#7-cm-plan-linkage-doc-wu-13)).

---

## 1. Reading the tables

- **Setting** — the required hardened configuration item.
- **Required value** — the value mandated by this Moderate baseline.
- **Controlling field** — the Helm value path (e.g.
  `admissionWebhook.securityContext.readOnlyRootFilesystem`) or the rendered
  manifest field / source file that establishes the value.
- **Status** —
  - **Enforced (current)** — the chart (or validated binary default) sets the
    required value today.
  - **Enforced (current) — `values.yaml` default, gated** — the value is
    populated in the shipped `values.yaml` and renders into the workload by
    default; the `manifest-hardening-gate` (conftest `restricted.pss`) **fails the
    build** if a rendered pod is missing it and `helm-unittest` asserts it. An
    operator may still override the value (e.g. `seccompProfile.type: Localhost`).
  - **Partial (Pn)** — a real capability ships but the control is not fully met by
    default; the residual is scoped to a phase / POA&M.
  - **Open gap (residual Pn)** — the chart does **not** set the value; tracked as a
    POA&M.
  - **Target (phase Pn)** — the chart does **not** yet enforce the value; the
    cited phase remediates it. POA&M IDs are linked.

All field paths are relative to `charts/kube-policies/`.

---

## 2. AST-WH — admission-webhook

Source manifests: `templates/admission-webhook-deployment.yaml`,
`templates/admission-webhook-tls.yaml`, `templates/configmap.yaml`,
`templates/rbac.yaml`. Listening ports: `8443/tcp` (TLS 1.3 AdmissionReview),
`9090/tcp` (HTTP metrics) per the facts sheet.

| Setting | Required value | Controlling field | Status |
|---|---|---|---|
| TLS minimum version | TLS 1.3 | Runtime validator `internal/config/config.go:175` (`security.tls.min_version` default `1.3`) and `:218` (rejects anything ≠ `1.3`). The webhook serves `8443` with this floor. The chart does **not** expose a Helm override; the binary enforces it. | Enforced (current) |
| Fail-closed enforcement | `fail-closed` | `templates/configmap.yaml` → `policy.failure_mode: "fail-closed"` (hardcoded literal, line 15). Reinforced at the admission layer by `admissionWebhook.webhook.failurePolicy: Fail` (`values.yaml`) rendered into the `ValidatingWebhookConfiguration` `webhooks[0].failurePolicy` (`templates/admission-webhook-tls.yaml:72`). | Enforced (current) |
| Webhook timeout | ≤ 10s | `admissionWebhook.webhook.timeoutSeconds: 10` → `webhooks[0].timeoutSeconds`. | Enforced (current) |
| CPU/memory limits | limits + requests set | `admissionWebhook.resources` (`values.yaml`: limits `500m`/`512Mi`, requests `100m`/`128Mi`) → container `resources` (`admission-webhook-deployment.yaml:109`). | Enforced (current) |
| runAsNonRoot | `true` | `admissionWebhook.podSecurityContext.runAsNonRoot: true` and `admissionWebhook.securityContext.runAsNonRoot: true` (UID `65534`). | Enforced (current) |
| readOnlyRootFilesystem | `true` | `admissionWebhook.securityContext.readOnlyRootFilesystem: true`. Writable paths confined to `emptyDir` mounts `/tmp` and `/var/log/kube-policies` (`admission-webhook-deployment.yaml:118-121`). | Enforced (current) |
| allowPrivilegeEscalation | `false` | `admissionWebhook.securityContext.allowPrivilegeEscalation: false`. | Enforced (current) |
| Drop ALL capabilities | `drop: [ALL]` | `admissionWebhook.securityContext.capabilities.drop: [ALL]`. | Enforced (current) |
| seccompProfile | `RuntimeDefault` (or `Localhost` + `localhostProfile`) | **`values.yaml` default**: `admissionWebhook.podSecurityContext.seccompProfile` / `admissionWebhook.securityContext.seccompProfile` ship `type: RuntimeDefault` in the shipped `values.yaml` and render straight into the pod/container `securityContext`. An operator may instead supply `type: Localhost` with a `localhostProfile` path. The gate (CFG-WU-12/22) `restricted.pss` + `helm-unittest` lock it on the rendered chart. | **Enforced (current) — `values.yaml` default, gated (P5)** — POAM-024 closed. |
| runAsGroup (non-zero) | `> 0` | **`values.yaml` default**: `admissionWebhook.podSecurityContext.runAsGroup` / `.securityContext.runAsGroup` ship `65534` in the shipped `values.yaml` and render into the `securityContext`; `helm-unittest` asserts it. | **Enforced (current) — `values.yaml` default, gated (P5)** — POAM-024 closed. |
| automountServiceAccountToken | `false` (with scoped pod-level opt-in) | `admissionWebhook.serviceAccount` sets `automountServiceAccountToken: false`; the webhook pod opts the token back in at the pod spec because it calls the apiserver (TokenReview / admission). The blanket SA default is **off**. | Enforced (current) — *IAM-WU-09/10; closes the POAM-024 automount milestone.* |
| TLS material provisioning | server cert + caBundle present | `admissionWebhook.tls.autoGenerate: true` (default) generates a self-signed CA + leaf; the `else` branch fails the render closed if no Secret, no inline PEM, and `autoGenerate=false` (`admission-webhook-tls.yaml:42-46`). | Enforced (current) — *self-signed default; cert-manager / apiserver mTLS is the target in P3.* |
| Metrics endpoint protection | TLS + authn on `9090` | `9090/tcp` is plain **HTTP, unauthenticated** (facts sheet; `--metrics-port=9090`). | **Target (phase P3)** — metrics TLS+authn. |
| Replica count (availability) | ≥ 2 | `admissionWebhook.replicaCount: 2` → Deployment `spec.replicas` (`admission-webhook-deployment.yaml:12`). No PodDisruptionBudget or anti-affinity yet. | Enforced (current, count) — *PDB/anti-affinity Target (phase P9).* |

---

## 3. AST-PM — policy-manager

Source manifests: `templates/policy-manager-deployment.yaml`,
`templates/configmap.yaml`, `templates/policy-manager-pvc.yaml`,
`templates/rbac.yaml`. Listening ports: `8080/tcp` (HTTP REST `/api/v1`),
`9091/tcp` (HTTP metrics).

| Setting | Required value | Controlling field | Status |
|---|---|---|---|
| TLS minimum version | TLS 1.3 | Runtime validator `internal/config/config.go` (`security.tls.min_version` floor) + `cmd/policy-manager/main.go` `ListenAndServeTLS` (P2/CRY-WU-05). `8080` serves **TLS 1.3 (server-auth)** by default from the mounted cert (cert-manager / autoGenerate). | Enforced (current) — *TLS 1.3 transport; OIDC authN/authZ is config-gated (auth.enabled, default off).* |
| Fail-closed enforcement | `fail-closed` | `templates/configmap.yaml` → `policy.failure_mode: "fail-closed"` (shared ConfigMap consumed by `--config=/etc/config/config.yaml`, `policy-manager-deployment.yaml:48`). | Enforced (current) |
| API authentication / authZ | OIDC + authZ on `8080` | `8080/tcp` REST API is **unauthenticated** today; internal decision POSTs use a static bearer token (`POLICY_MANAGER_INTERNAL_TOKEN`, `policy-manager-deployment.yaml:63`). | **Target (phase P2/P3)** — OIDC/authZ. |
| CPU/memory limits | limits + requests set | `policyManager.resources` (limits `500m`/`512Mi`, requests `100m`/`128Mi`) → container `resources` (`policy-manager-deployment.yaml:87`). | Enforced (current) |
| runAsNonRoot | `true` | `policyManager.podSecurityContext.runAsNonRoot: true` and `policyManager.securityContext.runAsNonRoot: true` (UID `65534`). | Enforced (current) |
| readOnlyRootFilesystem | `true` | `policyManager.securityContext.readOnlyRootFilesystem: true`; writable paths confined to `emptyDir` `/tmp` and (if `persistence.enabled`) the PVC at `/var/lib/kube-policies` (`policy-manager-deployment.yaml:89-98`). | Enforced (current) |
| allowPrivilegeEscalation | `false` | `policyManager.securityContext.allowPrivilegeEscalation: false`. | Enforced (current) |
| Drop ALL capabilities | `drop: [ALL]` | `policyManager.securityContext.capabilities.drop: [ALL]`. | Enforced (current) |
| seccompProfile | `RuntimeDefault` (or `Localhost` + `localhostProfile`) | **`values.yaml` default**: `policyManager.podSecurityContext.seccompProfile` / `policyManager.securityContext.seccompProfile` ship `type: RuntimeDefault`; `helm-unittest` + `restricted.pss` lock it. | **Enforced (current) — `values.yaml` default, gated (P5)** — POAM-024 closed. |
| runAsGroup (non-zero) | `> 0` | **`values.yaml` default**: `policyManager.podSecurityContext.runAsGroup` / `.securityContext.runAsGroup` ship `65534`; `helm-unittest` asserts it. | **Enforced (current) — `values.yaml` default, gated (P5)** — POAM-024 closed. |
| automountServiceAccountToken | `false` (with scoped pod-level opt-in) | SA `automountServiceAccountToken: false` (`rbac.yaml:35`); the PM pod opts back in (`dig ... true`) because it reconciles CRDs/Leases and calls TokenReview (ICX-06). The `tokenreview` internal-auth mode (chart default) **requires** the token, enforced by a `_helpers.tpl` guard. | Enforced (current) — *IAM-WU-09/10/11; closes the POAM-024 automount milestone.* |
| Durable audit storage | persistent (not `emptyDir`) | `persistence.enabled: true` renders the PVC (`policy-manager-pvc.yaml`); however the `AST-WH` audit file backend writes to an `emptyDir` (`admission-webhook-deployment.yaml:136`). | Target (phase P7) — *audit durability.* |
| Replica count / leader election | leader-elected; HA-capable | `policyManager.replicaCount: 1` → `spec.replicas`. Leader election via `coordination.k8s.io/Lease` is RBAC-granted (`rbac.yaml:105-108`) so scaling >1 is safe; default ships single replica. | Enforced (current, single replica + leader election) — *raise replicas + PDB in P9.* |
| Metrics endpoint protection | TLS + authn on `9091` | `9091/tcp` plain **HTTP, unauthenticated**. | **Target (phase P3)** — metrics TLS+authn. |

---

## 4. AST-DB — dashboard BFF (+ AST-SPA)

Source manifests: `templates/dashboard-deployment.yaml`,
`templates/dashboard-service.yaml`, `templates/dashboard-rbac.yaml`,
`templates/dashboard-ingress.yaml`. **Off by default**
(`dashboard.enabled: false`). Listening ports: `8090/tcp` (SPA + `/api` +
reverse-proxy), `9092/tcp` (HTTP metrics).

| Setting | Required value | Controlling field | Status |
|---|---|---|---|
| Read-only by default (write gate) | `ALLOW_WRITES=false` | `dashboard.allowWrites: false` (`values.yaml`) → container env `ALLOW_WRITES` (`dashboard-deployment.yaml:53-54`). Two-flag gate: writes require **both** `dashboard.enabled` and `dashboard.allowWrites` true; the SPA is otherwise read-only (`cmd/dashboard/proxy.go`). | Enforced (current) |
| Disabled by default (least functionality) | `enabled=false` | `dashboard.enabled: false` (`values.yaml`); all dashboard templates are guarded by `{{- if .Values.dashboard.enabled }}`. | Enforced (current) |
| CPU/memory limits | limits + requests set | `dashboard.resources` (limits `200m`/`256Mi`, requests `50m`/`64Mi`) → container `resources` (`dashboard-deployment.yaml:83`). | Enforced (current) |
| runAsNonRoot | `true` | **Values-driven** (UID `65532`): `dashboard.podSecurityContext.runAsNonRoot` / `dashboard.securityContext.runAsNonRoot` ship `true` in `values.yaml` and render via `toYaml` into `dashboard-deployment.yaml`. | Enforced (current) |
| readOnlyRootFilesystem | `true` | Container `securityContext.readOnlyRootFilesystem: true` (`dashboard-deployment.yaml:80`); writable path confined to `emptyDir` `/tmp`. | Enforced (current) |
| allowPrivilegeEscalation | `false` | Container `securityContext.allowPrivilegeEscalation: false` (`dashboard-deployment.yaml:76`). | Enforced (current) |
| Drop ALL capabilities | `drop: [ALL]` | Container `securityContext.capabilities.drop: [ALL]` (`dashboard-deployment.yaml:77-79`). | Enforced (current) |
| seccompProfile | `RuntimeDefault` | **`values.yaml` default**: the dashboard pod/container `securityContext` is now **values-driven** (`dashboard.podSecurityContext.seccompProfile` / `dashboard.securityContext.seccompProfile`, rendered via `toYaml`) and ships `type: RuntimeDefault`. The `restricted.pss` gate covers the dashboard and the `helm-unittest` dashboard suite asserts `seccompProfile`. | **Enforced (current) — `values.yaml` default, gated (P5)** — POAM-024 closed. |
| runAsGroup (non-zero) | `> 0` | **`values.yaml` default**: `dashboard.podSecurityContext.runAsGroup` / `.securityContext.runAsGroup` ship `65532` (distroless-nonroot GID), values-driven and asserted by `helm-unittest`. | **Enforced (current) — `values.yaml` default, gated (P5)** — POAM-024 closed. |
| automountServiceAccountToken | `false` | SA `automountServiceAccountToken: false` (`dashboard-rbac.yaml:12`) **and** the dashboard pod sets `automountServiceAccountToken: false` (`dashboard-deployment.yaml:43`) — the dashboard never calls the apiserver, so no token is mounted. | Enforced (current) — *IAM-WU-10; closes the POAM-024 automount milestone for the dashboard.* |
| RBAC least-privilege | namespaced read-only Role | `dashboard-rbac.yaml` grants a **namespaced** `Role` limited to `get` on two named Services (no CRDs, Secrets, or wildcard). This is a hardening bright spot relative to the shared cluster role. | Enforced (current) |
| User authentication | OIDC login on `8090` | `8090/tcp` served as **HTTP with no user authn** (write-gated only). | **Target (phase P3)** — TLS + OIDC login. |
| Ingress TLS | TLS configured when exposed | `dashboard.ingress.enabled: false` (default); `dashboard.ingress.tls: []` (`values.yaml`) — no TLS block populated. | Target (phase P3) — *populate ingress TLS when externally exposed.* |
| Replica count | ≥ 1 (UI tier) | `dashboard.replicaCount: 1` → `spec.replicas` (`dashboard-deployment.yaml:11`). | Enforced (current) |

---

## 5. AST-CHART — Helm chart (cross-cutting / namespace settings)

Source: `charts/kube-policies/values.yaml`, `templates/rbac.yaml`,
`templates/internal-token-secret.yaml`, `templates/configmap.yaml`.

| Setting | Required value | Controlling field | Status |
|---|---|---|---|
| Audit backend allowlist | `file` or `stdout` only | `audit.backend.type` (`values.yaml`); `templates/configmap.yaml:2-4` **fails the render** for any unsupported backend, and `internal/config/config.go` rejects it at runtime. | Enforced (current) |
| Fail-closed config (chart-wide) | `policy.failure_mode: fail-closed` | `templates/configmap.yaml:15` (shared ConfigMap consumed by both `AST-WH` and `AST-PM`). | Enforced (current) |
| RBAC least-privilege (core services) | scoped to required verbs/resources | `templates/rbac.yaml`: two **per-component** `ClusterRole`s (`AST-WH`, `AST-PM`) grant only `get,list,watch` on the `policies.kube-policies.io` CRDs plus `get,update,patch` on their `/status`; leader election is a **namespaced** `Role` (`coordination` Leases + namespaced `events`). The prior cluster-wide read on secrets/nodes/pods/serviceaccounts/RBAC and the `admissionregistration` write were removed (dead privilege — neither binary calls them). No wildcard verbs/resources. | Enforced (current) — *least-privilege split landed in P3 (IAM-WU-08); CI regression gate is IAM-WU-17.* |
| Per-component service accounts | one SA per component | `AST-WH` (`<fullname>-admission-webhook`), `AST-PM` (`<fullname>-policy-manager`), and `AST-DB` (`<fullname>-dashboard`, `dashboard-rbac.yaml`) each have their own SA bound only to its own role. `automountServiceAccountToken: false` on every SA, with explicit pod-level opt-in only on the webhook/manager (they call the apiserver); the dashboard never does. | Enforced (current) — *IAM-WU-09/10; audience-bound projected token replacing the static inter-service secret is IAM-WU-11.* |
| Internal token secrecy | randomized, not committed | `internalToken: ""` (`values.yaml`) → chart auto-generates a 48-char `randAlphaNum` token and preserves it across upgrades via `lookup` (`internal-token-secret.yaml:2-10`). | Enforced (current) — *static bearer; audience-bound token is the target in P3/P4.* |
| Image pull policy / pinning | digest-pinned (`@sha256`) | The `kube-policies.image` helper (`_helpers.tpl`) **supports** a digest-pinned reference: setting `*.image.tag` to a `tag@sha256:<digest>` value renders a valid pinned ref (`registry/repository:tag@sha256:…`), giving operators a **digest-deploy option** today. **However** the shipped `values.yaml` still uses floating tags (`tag: "1.0.0"`) with `pullPolicy: IfNotPresent`. | **Partial (P5)** — digest-deploy option supported; **not digest-pinned by default** — residual POAM-023 (CM-2). Digest-by-default + base-image pinning land in P6 (`scripts/pin-base-images.sh`). |
| NetworkPolicy (default-deny) | default-deny ingress+egress + scoped allows | **No NetworkPolicy template exists** in `templates/`. The `kube-policies-system` namespace is a flat open segment. | **Target (phase P4)** — POAM-007 (SC-7, Critical). |
| PSS namespace enforcement | `pod-security.kubernetes.io/enforce=restricted` | When the chart manages the namespace (`namespace.create=true`, or via `--create-namespace`), `templates/namespace.yaml` labels it `pod-security.kubernetes.io/enforce`, `audit`, and `warn` all = `restricted` (`namespace.podSecurity.*`, default `restricted`). **`namespace.create` defaults `false`**, so by default the operator owns the namespace and **must** apply the labels (or use `--create-namespace`); the `network-posture-gate` + `restricted.pss` conftest assert the labels on the rendered namespace. | Enforced (current, when chart-managed) — *POAM-024 PSS milestone; conditional on `namespace.create=true` / operator labeling.* |
| Workload-controller policy coverage | `spec.template.spec` traversal | Shipped policies do not traverse `spec.template.spec`; Deployments/DaemonSets/etc. and init/ephemeral containers are not evaluated. | **Target (phase P10)** — POAM-008 (CM-6, Critical). |

---

## 5A. Monitoring stack (DEMO/Kind-grade — not a production CI)

The example monitoring manifests under
`deployments/kubernetes/monitoring/` (prometheus, grafana, alertmanager) are an
**optional, demo/Kind-grade observability stack**, not an in-boundary control or a
production deployment. They are honestly bounded as follows:

| Setting | State | Status |
|---|---|---|
| Workload securityContext (restricted PSS) | The prometheus/grafana/alertmanager pods + containers set `runAsNonRoot`, a non-root UID, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, and `seccompProfile.type: RuntimeDefault` — they pass the `restricted.pss` conftest profile. | Enforced (current, manifests). |
| Storage / persistence | **`emptyDir` only — DEMO/Kind-grade, NO persistence.** The Prometheus TSDB, Grafana state, and `/tmp` are ephemeral and **lost on pod restart**. There is no PVC, no retention guarantee, and this is **not** an audit-durable or production store. | **Demo-only — not durable** (do not treat as evidence storage; AU durability is P7). |
| Namespace PSA labels | The shipped `kube-policies-monitoring` Namespace now carries `pod-security.kubernetes.io/{enforce,audit,warn}: restricted`, and the `restricted.pss` conftest covers the monitoring workloads. | Enforced (current, manifests) — *closed in P5; see [cis-benchmark-results.md](cis-benchmark-results.md).* |
| Authentication / exposure | Grafana ships a demo admin Secret; the stack is for local/Kind demonstration. | **Demo-only** — not for production exposure. |

These manifests are **out of the authorization boundary** (the Prometheus scraper
is `AST-EXT-PROMETHEUS` in `ZONE-EXT`, [inventory.md](inventory.md)) and must not
be read as a shipped, persistent, or authorized monitoring control.

---

## 6. Deviation / exception process

This baseline is a **mandatory** configuration. Any deployment that departs
from a setting marked **Enforced (current)** — for example, setting
`admissionWebhook.webhook.failurePolicy: Ignore`, `dashboard.allowWrites: true`
in production, weakening a `securityContext` value, or installing with
`rbac.create: false` against a pre-existing over-privileged SA — constitutes a
**configuration deviation** and requires a documented, time-bound exception.

**Process (governed by the [Configuration Management Plan](plans/configuration-management-plan.md), CM-3):**

1. **Request.** The requester records the specific Helm value path / manifest
   field, the required baseline value, the requested deviation value, the
   business/technical justification, the compensating controls, and a proposed
   expiry date. Routine changes additionally complete the
   [change-control checklist in the pull-request template](../../.github/pull_request_template.md)
   (baseline + inventory updated, policy/hardening gates green, images digest-pinned).
2. **Risk review.** The ISSO (TBD — assign before assessment) assesses residual
   risk against the affected control(s) (CM-6, plus any control the setting
   implements — e.g. SC-7 for NetworkPolicy, AC-3 for the dashboard write gate).
3. **Approval.** The Authorizing Official (TBD — assign before assessment), or a
   delegate named in the CM Plan, approves or denies. Approved deviations are
   **time-bound** and reviewed at each annual baseline review (and on expiry).
4. **Record.** Approved deviations are recorded as a **POA&M** entry in
   [poam.csv](poam.csv) (with severity and `scheduled_completion`) and noted in
   the affected row of the [control matrix](control-matrix.csv). Unremediated
   chart gaps in this document (the **Target (phase Pn)** rows) are themselves
   tracked as POA&M items — see POAM-007, POAM-008, POAM-023, POAM-024.
5. **Roles.** All roles above use titles only; named individuals are assigned
   per [roles-raci.md](roles-raci.md) before assessment.

No deviation is permitted to the **fail-closed** posture
(`policy.failure_mode`, `failurePolicy: Fail`) or the **TLS 1.3** floor without
AO approval and a compensating-control analysis, because these are the system's
shipped security boundaries.

---

## 7. CM Plan linkage

This baseline is **validated by the configuration-as-code work in phase P5**:
the chart templates and `values.yaml` are the machine-readable expression of
the settings above, and P5 delivered (a) **digest-pinned image support** (the
`kube-policies.image` helper accepts a `tag@sha256:…` reference — a digest-deploy
option, though shipped values still use floating tags; residual POAM-023), (b) the
P5 hardening items — `seccompProfile: RuntimeDefault` (or `Localhost` +
`localhostProfile`) and a non-root `runAsGroup` shipped as **`values.yaml`
defaults** on **all three** workloads (`POAM-024` closed), the dashboard
`securityContext` made **values-driven**, `automountServiceAccountToken=false` on
every SA, and the **PSS `restricted`** namespace labels (when chart-managed) — and
(c) the **CI gates** that render the chart and assert these settings on the rendered
manifests, so drift from this baseline is caught at build time. The remaining
residual is images not digest-pinned by default (POAM-023). The example monitoring
manifests stay demo-grade (`emptyDir`, no persistence) — an availability concern
(AU durability is P7), not a CM-7 hardening gap.

The gating CI jobs (in `.github/workflows/ci.yml`) that enforce this baseline are:

- `manifest-hardening-gate` — conftest `restricted.pss` over the rendered chart
  (CFG-WU-12), plus a dead-gate proof that strips `seccompProfile` and asserts the
  render is then **denied**;
- `helm-unittest` — `charts/kube-policies/tests/hardening_test.yaml` asserts the
  restricted control set (incl. `seccompProfile`+`runAsGroup`) per pod/container
  across the control plane **and** the dashboard (CFG-WU-22);
- `network-posture-gate` — default-deny + per-component ingress + PSA-restricted
  namespace labels (NET-WU-20);
- `rbac-sa-gate` — RBAC least-privilege + SA-token automount (IAM-WU-17);
- the **gating Trivy** filesystem + image scans (`CRITICAL,HIGH` fail the build),
  strengthening RA-5 / SI-2.

This baseline is the authoritative **CM-2 baseline configuration** and **CM-6
configuration settings** record adopted by the now-published
[Configuration Management Plan](plans/configuration-management-plan.md)
(CM-1 / CM-3 / CM-9; see also the [CM policy](policies/CM-policy.md) and
[CM procedures](procedures/CM-procedures.md)). Change control is enforced by the CI
gates above and the [pull-request change-control checklist](../../.github/pull_request_template.md);
drift between the running state and this baseline is detected by
[`scripts/ops/drift-detect.sh`](../../scripts/ops/drift-detect.sh)
(see [drift-detection.md](drift-detection.md)).

**Control matrix rows:** `CM-7` (Least Functionality) is now **Implemented** (P5;
POAM-024 closed); `CM-2` (Baseline Configuration) and `CM-6` (Configuration
Settings) remain **Partial** (P5; honest residuals above — POAM-023 / POAM-008);
`CM-1` and `CM-9` are **Implemented** and `CM-3` is **Partial**, per
[control-matrix.csv](control-matrix.csv).
