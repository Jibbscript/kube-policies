---
title: "System Security Plan (SSP) — Kube-Policies (KP)"
control_family: "PL"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# System Security Plan — Kube-Policies (KP)

FIPS-199 categorization: **Moderate**. Standard: **NIST SP 800-53 Rev 5**, **FedRAMP Moderate**
baseline. This SSP is a Draft skeleton for a Proof-of-Concept being driven to assessment readiness;
most controls are **Planned** or **Partial** and statuses are tracked in the
[control matrix](../control-matrix.csv). This plan is reviewed at least **annually** (next review
2027-05-29) and upon any significant change to the system.

> Honesty note: "current" descriptions reflect the as-built PoC, which has known foundational gaps
> (no validated FIPS module, audit on `emptyDir`, untrustworthy CI, and planes whose
> authentication/TLS are config-gated and off by default). NetworkPolicy segmentation now ships
> in the chart (P4) but **requires a NetworkPolicy-enforcing CNI** and its live e2e proof is not
> yet run, so SC-7 is "Implemented (Helm) — requires enforcing CNI", not enforced by default.
> These are recorded in the [POA&M](../poam.csv) and remediated across phases P1–P12. Nothing
> here should be read as an authorization to operate.

---

## 1 System Identification & Categorization

- **System name:** Kube-Policies (Kubernetes admission-control & policy-management)
- **System abbreviation:** KP
- **Repository:** `github.com/Jibbscript/kube-policies`
- **Deployment model:** Helm chart (`charts/kube-policies`) into a single Kubernetes namespace
  (`kube-policies-system`) on a customer/CSP-provided cluster.
- **FIPS-199 categorization (target):** **Moderate** — Confidentiality: Moderate, Integrity:
  Moderate, Availability: Moderate. The high-water-mark rationale, information types
  (IT-1 configuration & policy data, IT-2 admission decision audit records, IT-3 operational
  metrics), and SP 800-60 mapping are defined in the
  [FIPS-199 categorization](../categorization/FIPS-199.md).
- **Baseline:** NIST SP 800-53 Rev 5, FedRAMP **Moderate**.

The authoritative system facts (component names, asset IDs, ports, trust zones, interconnections)
are pinned in the [system facts sheet](../system-facts.md) and are used verbatim throughout this SSP.

## 2 System Description

Kube-Policies is a Kubernetes admission-control and policy-management system. It intercepts
AdmissionReview requests from the kube-apiserver, evaluates them against OPA/Rego policies, records
allow/deny decisions, and exposes a management API and dashboard. Components (see the
[system facts sheet](../system-facts.md), summarized below):

- **`AST-WH` — admission-webhook** (Go): validating/mutating webhook serving `/validate` and
  `/mutate` on `8443/tcp` (TLS 1.3) with metrics on `9090/tcp`. Ships **fail-closed** by default.
- **`AST-PM` — policy-manager** (Go): REST API `/api/v1` on `8080/tcp` with metrics on `9091/tcp`;
  reconciles the `Policy`/`PolicyException` CRDs and runs leader election against the kube-apiserver.
- **`AST-DB` — dashboard BFF** (Go): serves the SPA, a BFF `/api`, and a reverse-proxy
  `/api/v1`→`AST-PM:8080` on `8090/tcp` with metrics on `9092/tcp`. **Read-only** unless
  `ALLOW_WRITES=true`.
- **`AST-SPA` — Svelte dashboard SPA**: static assets embedded in and served by `AST-DB`.
- **`AST-OPA` — OPA/Rego policy evaluator**: embedded Go library inside `AST-WH` and `AST-PM`
  (no listening port).
- **`AST-CRD-POL` — `Policy` CRD** and **`AST-CRD-EXC` — `PolicyException` CRD**: namespaced
  CustomResourceDefinitions stored by the kube-apiserver.
- **`AST-CHART` — Helm chart**: deployment artifact carrying RBAC, Services, and configuration.
- **Container images:** `AST-IMG-WH`, `AST-IMG-PM`, `AST-IMG-DB` (distroless bases; registry/tag/
  digest operator-supplied, pinning addressed in P6).

The full asset register (asset IDs, images, versions, ports, boundary) is maintained in the
[inventory](../inventory.csv).

## 3 System Environment & Architecture

Kube-Policies runs entirely within the `kube-policies-system` namespace on a customer/CSP-provided
Kubernetes cluster. Two trust zones apply:

- **`ZONE-EXT`** (outside the boundary): kube-apiserver, Prometheus scraper, cluster operators/users,
  and the hosting CSP control plane and infrastructure.
- **`ZONE-SYS`** (inside the boundary): the namespace workloads (`AST-WH`, `AST-PM`,
  `AST-DB`/`AST-SPA`) and the namespaced CRDs (`AST-CRD-POL`, `AST-CRD-EXC`).

The authorization boundary and component placement are depicted in the
[authorization boundary diagram](../diagrams/authorization-boundary.md); request and audit data
movement across interconnections `ICX-01`..`ICX-06` is depicted in the
[data-flow diagram](../diagrams/data-flow.md). External and internal interconnections
(`ICX-01`..`ICX-06`) are enumerated with sensitivity and protection mechanism in the
[interconnection register](../interconnections.md), and inventoried per-control in the
[control matrix](../control-matrix.csv).

## 4 Ports, Protocols & Services

The complete listening-port register — every port from the facts sheet (`8443`, `9090`, `8080`,
`9091`, `8090`, `9092`) with its service, transport, and purpose — is maintained in the
[Ports, Protocols & Services table](ports-protocols-services.md). That register is the source of
truth for CM-7 (least functionality) and SC-7 (boundary protection).

## 5 Roles & Responsibilities

Named roles are **not yet staffed**; assign before assessment. See the
[roles & RACI matrix](../roles-raci.md) for the authoritative responsibility assignment.

| Role | Holder | Responsibility (summary) |
|---|---|---|
| System Owner | TBD — assign before assessment | Overall system accountability, resourcing, SSP maintenance, accepts operational risk within delegation. |
| ISSO (Information System Security Officer) | TBD — assign before assessment | Day-to-day security operations, control implementation oversight, POA&M tracking, evidence custody. |
| AO (Authorizing Official) | TBD — assign before assessment | Risk acceptance and authorization decision (ATO). |
| Independent Assessor | TBD — assign before assessment | Independent control assessment (SAR). |

## 6 Laws, Regulations & Standards

- **FISMA** (Federal Information Security Modernization Act).
- **FedRAMP** — Moderate baseline authorization requirements.
- **NIST SP 800-53 Rev 5** — Security and Privacy Controls.
- **NIST SP 800-53B** — Control Baselines.
- **FIPS-199** — Standards for Security Categorization (see [categorization](../categorization/FIPS-199.md)).
- **FIPS-200** — Minimum Security Requirements.
- **NIST SP 800-60** — Information type categorization basis.
- **FIPS-140-3** — Cryptographic Module Validation (current gap; tracked in the [POA&M](../poam.csv)).
- **OMB A-130** — Managing Information as a Strategic Resource.

## 7 Control Implementation Summary

Each NIST SP 800-53 Rev 5 control family in the FedRAMP Moderate baseline is summarized below. The
narratives are a faithful transformation of the [control matrix](../control-matrix.csv) — the
authoritative per-control register of status, responsible party, implementing artifact, remediating
phase, and evidence — into SSP prose; the [POA&M](../poam.csv) carries the open weaknesses and the
[CRM](../CRM.md) is the authoritative responsibility allocation. **Statuses below mirror the matrix
exactly and are not upgraded here.** Each family lists every in-scope control with its status and
responsible party; each `Implemented` / `Implemented (Helm)` / `Partial` control carries a short
implementation narrative citing its implementing artifact and the evidencing test/work-unit (WU);
`Planned` / `Inherited` / `Not-Applicable` / `Customer` controls carry a brief status line and the
matrix rationale. Statuses use the matrix vocabulary: **Implemented**, **Implemented (Helm) —
requires enforcing CNI**, **Partial** (typically config-gated or pending first-CI-run evidence),
**Planned** (deferred to a remediating phase), **Inherited** (from the hosting CSP / cluster IdP),
**Customer** (operator-owned), and **Not-Applicable**.

> Honesty scope: this PoC has no ATO. Where a control is config-gated (chart default off) or its
> CI/branch-protection enforcement is configured-but-not-yet-executed, the matrix records **Partial**
> and so does this plan — those are not Implemented. Nothing here is an authorization to operate.

### 7.1 AC — Access Control

**Allocation: Shared** ([CRM §AC](../CRM.md)). Access enforcement spans two planes: an OIDC + deny-by-default
RBAC **management** plane that is **config-gated** (chart default `auth.enabled: false`, i.e. an
unauthenticated dev-gap) and an **unconditionally-authenticated decision plane**. The full code-grounded
treatment is in the [IAM control narrative](../iam-control-narrative.md); policy and procedures are the
[AC policy](../policies/AC-policy.md) and [AC procedures](../procedures/AC-procedures.md). Cluster RBAC,
the OIDC IdP, account lifecycle (AC-2 enhancements), and remote-access monitoring are Customer/Shared and
deferred to P3/P9/P12.

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| AC-1 | Implemented | System | AC-1 access-control policy + procedures authored ([AC-policy.md](../policies/AC-policy.md), [AC-procedures.md](../procedures/AC-procedures.md)) with an annual-review cadence. Evidence: `scripts/validate/compliance_check.py` doc-link/structure gate + docs markdown-link-check (CA-WU-01). Program-wide -1 rollup tracked in POAM-010. |
| AC-2 | Partial | System | Group→role model (viewer/editor/admin) maps OIDC groups via `RoleBindings` in `internal/policymanager/authz.go`, but enforcement is config-gated (`security.authentication.enabled`; chart default false). Evidence: `authz_test.go` + `router_authn_test.go` (IAM-WU-01). POAM-001. |
| AC-2(1)/(2)/(3)/(4)/(5) | Planned | System | Automated/temporary/emergency account management, disablement, audit actions, and inactivity logout depend on P3 IdP integration (+P7 audit pipeline for (4)). POAM-001 (AC-2(1)). |
| AC-2(12) | Planned | Shared | Atypical-usage account monitoring via SIEM/alerting in P9. |
| AC-2(13) | Planned | CSP | Disable high-risk accounts — procedural, depends on CSP HR/IdP process (P12). |
| AC-3 | Partial | System | Deny-by-default RBAC (`requiredRoles` + `RBACMiddleware`, `internal/policymanager/authz.go`) on the mgmt plane is config-gated; the decision plane (`/decisions/*`) is authed unconditionally via TokenReview (Inc7). Evidence: `authz_test.go` + `decisions_read_auth_test.go` + `router_authn_test.go` (IAM-WU-01). POAM-001. |
| AC-4 | Planned | System | No NetworkPolicy information-flow control yet; default-deny + scoped flows ship in P4 (`charts/kube-policies/templates/`, NetworkPolicy). POAM-004. |
| AC-5 | Partial | System | Workload split enforced unconditionally (3 distinct SAs / 3 ClusterRoles; TokenReview grant on policy-manager only) in `charts/kube-policies/templates/rbac.yaml`; app-layer viewer/editor/admin separation is config-gated. Evidence: rbac-sa-gate (`test/policy/rbac_leastprivilege.rego` + `sa_token.rego` conftest, both modes) (IAM-WU-17). |
| AC-6 | Partial | System | Per-plane least-privilege RBAC enforced (CRD get/list/watch + status patch only; TokenReview create on PM only; dashboard read-only on 2 Services) in `rbac.yaml`; app-layer least-priv (`requiredRoles`) config-gated. Evidence: rbac-sa-gate (`test/policy/rbac_leastprivilege.rego` conftest; fail-fixture denies wildcard/cluster-Secrets grants) (IAM-WU-17). POAM-001. |
| AC-6(2) | Partial | System | Containers run non-root with no privilege escalation (`charts/kube-policies/values.yaml`); formalized in P5. Evidence: manifest-hardening-gate (`test/policy/restricted-pss.rego` conftest) + `charts/kube-policies/tests/hardening_test.yaml` (CFG-WU-12). |
| AC-6(1)/(5)/(9)/(10) | Planned | System | Security-function authZ, privileged-account restriction, privileged-function logging, and non-privileged-user restriction refined via P3 RBAC split (+P7 audit for (9)). |
| AC-6(7) | Planned | CSP | Periodic user-privilege review — procedural (P12). |
| AC-7 | Inherited | Customer | Unsuccessful-logon lockout thresholds inherited from the federated IdP; verified in P3. |
| AC-8 | Planned | System | System-use notification/login banner added to dashboard OIDC login in P3. |
| AC-11 / AC-11(1) | Inherited | Customer | Device lock / pattern-hiding displays are operator-workstation endpoint controls; inherited. |
| AC-12 | Planned | System | Automatic session termination via dashboard OIDC session management (P3). |
| AC-14 | Planned | System | Define unauthenticated-allowed actions (healthz/readyz) in `cmd/dashboard/proxy.go`; rest gated in P3. |
| AC-17 | Partial | System | No general remote-access service; reachable planes serve TLS 1.3, the mgmt plane adds OIDC bearer (config-gated) + optional mTLS via `internal/policymanager/auth_middleware.go`. Evidence: `auth_middleware_test.go` + `internal/config/tls_test.go` + `mtls_test.go` (IAM-WU-03). POAM-003. |
| AC-17(1) | Planned | Shared | Remote-access monitoring via ConMon/SIEM in P9. |
| AC-17(2)/(3)/(4) | Planned | System/Shared | Mgmt-plane TLS termination (P3, POAM-003), managed access points via ingress + NetworkPolicy (P4), and privileged-command gating (P3). |
| AC-18 / AC-18(1) | Not-Applicable | Customer | No wireless components in the boundary. |
| AC-19 | Inherited | Customer | Mobile-device control inherited from operator CSP/MDM. |
| AC-20 / AC-20(1)/(2) / AC-21 | Planned | CSP | External-system rules of behavior and information-sharing — procedural, authored in P12. |
| AC-22 | Not-Applicable | System | System publishes no public-facing content; admin-only planes. |

### 7.2 AT — Awareness and Training

**Allocation: Customer-Responsibility** (System provides AT-1 policy only) ([CRM §AT](../CRM.md)). The
organizational security-awareness program is operator-owned and not repository-resolvable.

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| AT-1 | Planned | CSP | AT-1 policy artifact authored ([AT-policy.md](../policies/AT-policy.md)); the matrix records this row Planned pending the P12 program. POAM-010. |
| AT-2 / AT-2(2)/(3) | Planned | CSP | Organizational security-awareness training incl. insider-threat and social-engineering modules (P12). |
| AT-3 | Planned | CSP | Role-based training for ISSO/admins (P12). |
| AT-4 | Planned | CSP | Training-record retention (P12). |

### 7.3 AU — Audit and Accountability

**Allocation: Shared** ([CRM §AU](../CRM.md)). The webhook emits structured admission **decision audit
records** (information type IT-2) for every allow/deny; current gaps — additional content, durable storage
(audit on `emptyDir` today), tamper-evidence, and retention/forwarding — are remediated in P7, with central
review/SIEM in P9. Policy and procedures: [AU policy](../policies/AU-policy.md), [AU procedures](../procedures/AU-procedures.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| AU-1 | Planned | CSP | AU-1 policy authored ([AU-policy.md](../policies/AU-policy.md)); Planned pending P12. POAM-010. |
| AU-2 | Partial | System | Webhook logs every allow/deny decision (`internal/audit/logger.go`); mgmt-plane events + event-list completeness in P7. Evidence: `logger_test.go` + `logger_p7_test.go` + `public_event_test.go` (AUD-WU-01). POAM-002. |
| AU-3 | Partial | System | Event struct captures who/what/when/decision (`internal/audit/logger.go`); missing src-IP/UA/req-URI added in P7. Evidence: `logger_p7_test.go` + `logger_test.go` (AUD-WU-03). POAM-002. |
| AU-3(1) | Planned | System | Add source IP, user-agent, request-URI, apiserver-id in P7. POAM-002. |
| AU-4 | Planned | System | Audit currently on `emptyDir`; durable PVC + capacity sizing (`charts/kube-policies/templates/policy-manager-pvc.yaml`) in P7. POAM-002. |
| AU-5 | Planned | System | Audit-failure alerting wired in P7/P9. |
| AU-6 / AU-6(1)/(3) / AU-7 / AU-7(1) | Planned | Shared | Central review, automated SIEM correlation, cross-repository correlation, and reduction/reporting provided by the SIEM in P9. |
| AU-8 | Partial | System | Records carry timestamps (`internal/audit/logger.go`); dual-UTC + authoritative time source formalized in P7. Evidence: `logger_p7_test.go` + `logger_test.go` (AUD-WU-05). |
| AU-9 / AU-9(3) | Planned | System | No tamper protection today; HMAC signing/chain over audit records + access restriction (`internal/audit/logger.go`) in P7. POAM-002. |
| AU-9(2) | Planned | Shared | Forwarding to a separate SIEM store in P7/P9. |
| AU-9(4) | Planned | System | Restrict audit access to the ISSO subset via RBAC in P3/P7. |
| AU-11 | Planned | Shared | FedRAMP retention policy set in P7; long-term in SIEM (P9). |
| AU-12 | Partial | System | Webhook generates decision records (`internal/admission/controller.go`); mgmt-plane API audit generation added in P7. Evidence: `audit_context_test.go` + `controller_test.go` + `manager_audit_test.go` (AUD-WU-02). |
| AU-12(1) | Planned | System | System-wide time-correlated trail across components in P7/P9. |

### 7.4 CA — Assessment, Authorization, and Monitoring

**Allocation: Shared** ([CRM §CA](../CRM.md)). The System authors the assessment/authorization artifacts
(this SSP, the [CRM](../CRM.md), the [control matrix](../control-matrix.csv), the
[interconnection register](../interconnections.md), and the [network-architecture](../network-architecture.md)
CA-3 allowed-flow record); the ATO decision, 3PAO engagement, and operating ConMon are Customer/CSP.
Policy and procedures: [CA policy](../policies/CA-policy.md), [CA procedures](../procedures/CA-procedures.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| CA-1 | Planned | CSP | CA-1 policy authored ([CA-policy.md](../policies/CA-policy.md)); Planned pending P12. POAM-010. |
| CA-2 / CA-2(1)/(2)/(3) | Planned | CSP | Independent control assessment, independent assessor, pen-test/specialized assessment, and leveraging CSP/3PAO results scheduled in P12. |
| CA-3 | Partial | System | Scoped allowed-flow record (every flow F1..F11 mapped to its NetworkPolicy template) in [network-architecture.md](../network-architecture.md), complementing the ICX-01..06 [interconnection register](../interconnections.md); formal interconnection security agreements remain TBD. Evidence: network-posture-gate (`test/policy/network_posture.rego` conftest over rendered NetworkPolicies) + `scripts/validate/compliance_check.py` doc-link gate (NET-WU-17). |
| CA-5 | Partial | CSP | POA&M established ([poam.csv](../poam.csv)); driven to closure across P1–P12. |
| CA-6 | Planned | CSP | AO (TBD — assign) authorization decision in P12. |
| CA-7 / CA-7(4) | Planned | Shared | ConMon program and integrated risk monitoring stood up in P9. |
| CA-7(1) | Planned | CSP | Independent ConMon assessment in P12. |
| CA-8 | Partial | CSP | DAST (ZAP baseline scan) added in P11 ([`.github/workflows/dast.yml`](../../../.github/workflows/dast.yml)); independent pen test remains P12. |
| CA-9 | Planned | System | Internal connections (ICX-02/04/06) documented in [system-facts.md](../system-facts.md); mTLS/TLS in P4. |

### 7.5 CM — Configuration Management

**Allocation: Shared** ([CRM §CM](../CRM.md)). The System ships a documented secure-configuration baseline,
the Helm chart/CRDs as the configuration artifacts, a least-functionality distroless posture, and a
[Configuration Management Plan](../plans/configuration-management-plan.md); the customer owns its own cluster
CM and the decision to admit the chart. Policy and procedures: [CM policy](../policies/CM-policy.md),
[CM procedures](../procedures/CM-procedures.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| CM-1 | Implemented | System | CM policy + procedures authored ([CM-policy.md](../policies/CM-policy.md), [CM-procedures.md](../procedures/CM-procedures.md)) with annual review and a designated ISSO official; family -1 satisfied. Evidence: `compliance_check.py` doc-link/structure gate + docs markdown-link-check (CFG-WU-01). Program-wide -1 rollup in POAM-010. |
| CM-2 | Partial | System | Secure-configuration baseline (CM-2/CM-6) formalized/versioned ([secure-configuration-baseline.md](../secure-configuration-baseline.md), `charts/kube-policies/values.yaml`, `scripts/ops/drift-detect.sh`); image helper accepts a digest-pinned ref. RESIDUAL: shipped values use floating tags (operator must pin) — POAM-023 Open. Evidence: `charts/kube-policies/tests/hardening_test.yaml` (helm-unittest) + manifest-hardening-gate (CFG-WU-12). |
| CM-2(2) | Planned | System | Helm-rendered baseline + CI drift checks (`charts/kube-policies/`) in P5. |
| CM-2(3) | Planned | System | Previous configurations retained in VCS (git history); formalized in P5. |
| CM-3 | Partial | System | Change control via PR review + CM-3 PR-template checklist enforced by the now-gating CI jobs ([configuration-management-plan.md](../plans/configuration-management-plan.md), `.github/pull_request_template.md`, `.github/workflows/ci.yml`); formal CCB membership + signed-commit/branch-protection enforcement remain TBD. Evidence: ci-gate aggregation job (`.github/workflows/ci.yml` needs rbac-sa-gate, manifest-hardening-gate, network-posture-gate, helm-unittest, security-scan) (CFG-WU-13). |
| CM-3(2) | Planned | System | Change testing via CI quality gates in P11. |
| CM-4 | Planned | System | Security-impact analysis in the PR process (P11). |
| CM-5 | Planned | System | Branch protection + CODEOWNERS + signed commits (P1). |
| CM-6 | Partial | System | Config validation enforces TLS 1.3/failure-mode (`internal/config/config.go`); P5 shipped CIS-restricted securityContext (seccompProfile=RuntimeDefault + non-root runAsGroup) as values defaults on all three workloads. RESIDUAL: the engine does not yet traverse `spec.template.spec` — POAM-008 (P10). Evidence: `config_test.go` + manifest-hardening-gate (`restricted-pss.rego`) + `hardening_test.yaml` (CFG-WU-12). |
| CM-6(1) | Planned | System | CI renders + verifies settings (helm template gate) in P5. |
| CM-7 | Implemented | System | Distroless images, dropped caps, readOnlyRootFilesystem; the [PPS register](ports-protocols-services.md) justifies each listening port; namespace ships PSA enforce/audit/warn=restricted (operator-conditional); seccompProfile=RuntimeDefault + non-root runAsGroup are values defaults on all three workloads; automountServiceAccountToken disabled per-SA (`charts/kube-policies/values.yaml`). POAM-024 Resolved. Evidence: manifest-hardening-gate (`restricted-pss.rego` conftest, fail-fixture self-test) + `hardening_test.yaml` (CFG-WU-12). |
| CM-7(1) | Partial | System | Periodic least-functionality / enabled-port review procedure defined in [CM-procedures.md](../procedures/CM-procedures.md) (annual + per significant change); first independent review at assessment (P12). Evidence: `compliance_check.py` doc-link/structure gate + docs markdown-link-check (CFG-WU-01). |
| CM-7(2)/(5) | Planned | System | Image/exec policy enforcement (`internal/policy/engine.go`) extended in P10; image-signature/allowlist admission in P6/P10. |
| CM-8 | Partial | System | [inventory.csv](../inventory.csv)/[inventory.md](../inventory.md) document per-component images with a digest column + digest-pinned-ref support and the CM-8 review cadence. RESIDUAL: SBOM-driven auto-update + unauthorized-component detection are P6. Evidence: `compliance_check.py` (inventory.csv asset_id non-blank/unique + inventory↔boundary consistency gate) (CFG-WU-11). |
| CM-8(1)/(3) | Planned | System | Inventory auto-update from SBOM and scan-driven unauthorized-component detection in P6. |
| CM-9 | Implemented | System | Configuration Management Plan authored ([configuration-management-plan.md](../plans/configuration-management-plan.md)) covering CM-1/CM-3/CM-9: baseline scope, CI-gate change control, Helm/CRD process, CCB/approval roles, annual review. Named CCB members remain TBD. Evidence: `compliance_check.py` doc-link/structure gate + docs markdown-link-check (CFG-WU-13). |
| CM-10 | Planned | CSP | Software-usage restrictions policy in P12. |
| CM-11 | Planned | System | Immutable distroless images + readOnlyRootFilesystem restrict installs (`charts/kube-policies/values.yaml`); formalized in P5. |
| CM-12 | Planned | System | Information types IT-1..3 located in CRDs/audit; documented in [system-facts.md](../system-facts.md), finalized P12. |
| CM-14 | Planned | System | Cosign signing + signature-verifying admission in P6. POAM-006. |

### 7.6 CP — Contingency Planning

**Allocation: Shared** ([CRM §CP](../CRM.md)). Application-level resilience (PDBs, anti-affinity, leader
election, DR runbooks) is delivered in P8; alternate sites and telecommunications are CSP-Inherited; etcd/CRD
backup/restore and the organizational contingency plan are Customer. Policy: [CP policy](../policies/CP-policy.md);
plan: [contingency-plan.md](../plans/contingency-plan.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| CP-1 | Planned | CSP | CP-1 policy authored ([CP-policy.md](../policies/CP-policy.md)); Planned pending P12. POAM-010. |
| CP-2 / CP-2(3) | Planned | Shared | Contingency plan + mission-resumption objectives authored in P8 ([contingency-plan.md](../plans/contingency-plan.md)). |
| CP-2(1) | Planned | CSP | Coordinate with IR/CSP DR plans in P12. |
| CP-2(8) | Partial | System | Critical assets (AST-WH gatekeeper) identified in [inventory.csv](../inventory.csv); RTO/RPO in P8. Evidence: `compliance_check.py` (inventory.csv + inventory↔boundary consistency gate) (RES-WU-01). |
| CP-3 | Planned | CSP | Contingency training in P12. |
| CP-4 / CP-4(1) | Planned | Shared/CSP | DR/restore testing in P8; coordinated test with CSP plans in P12. |
| CP-6 / CP-6(1)/(3) / CP-7 / CP-7(1)/(2)/(3) / CP-8 / CP-8(1)/(2) | Inherited | Customer | Alternate storage/processing sites and telecommunications services (incl. separation, accessibility, priority of service, single-points-of-failure) inherited from the hosting CSP infrastructure; backup targets defined in P8. |
| CP-9 / CP-9(1) | Planned | Shared | CRDs in etcd (CSP-backed); app-state/audit backup procedure + restore-reliability testing (`charts/kube-policies/templates/policy-manager-pvc.yaml`) defined in P8. POAM-007. |
| CP-10 | Partial | System | Leader election + replicas aid recovery (`cmd/admission-webhook/main.go`); full reconstitution/RTO-RPO in P8. Evidence: `test/integration/leader_election_test.go` + `test/e2e/state_recovery_test.go` + `test/e2e/backup_restore_test.go` (RES-WU-02). |
| CP-10(2) | Planned | System | Decision/transaction recovery semantics defined in P8. |

### 7.7 IA — Identification and Authentication

**Allocation: Shared** ([CRM §IA](../CRM.md)). Service-to-service identity (apiserver mTLS to the webhook,
audience+subject-bound projected SA tokens via TokenReview) is the bright spot; human OIDC authN to the mgmt
API is **config-gated** (chart default off). Human IdP/OIDC, MFA, and PIV are inherited from the federated IdP;
no FIPS-validated module exists today (P2). The full treatment is in the [IAM control narrative](../iam-control-narrative.md);
policy and procedures: [IA policy](../policies/IA-policy.md), [IA procedures](../procedures/IA-procedures.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| IA-1 | Planned | CSP | IA-1 policy authored ([IA-policy.md](../policies/IA-policy.md)); Planned pending P12. POAM-010. |
| IA-2 | Partial | System | OIDC ID-token bearer authN (issuer/JWKS/FIPS-alg allow-list/audience) on the mgmt API is config-gated (`security.authentication.enabled`; chart default false) — `internal/policymanager/auth_middleware.go`. Evidence: `auth_middleware_test.go` + `router_authn_test.go` (IAM-WU-01). POAM-001. |
| IA-2(1)/(2)/(8)/(12) | Planned | Shared/System | MFA (priv/non-priv), replay-resistant tokens, and PIV acceptance enforced by / inherited from the federated IdP; integrated/verified in P3. |
| IA-3 | Partial | System | Service identity enforced: audience+subject-bound projected SA tokens via TokenReview (default mode) + optional mTLS client certs (`internal/policymanager/tokenreview.go`); static shared-secret fallback is demo/non-cluster only. Evidence: `tokenreview_test.go` + `internal/config/client_mtls_test.go` (IAM-WU-04). POAM-003. |
| IA-4 | Planned | Shared | Identifier management via IdP; service identities in P3. |
| IA-5 | Partial | System | Bearer-token (FIPS CSPRNG gen, constant-time verify, 2-token rotation) + cert (cert-manager ECDSA P-256, hot reload) lifecycles implemented (`internal/auth/token.go`); the remaining Helm chart-side CSPRNG token generation is a tracked gap. Evidence: `token_test.go` + `internal/tlsreload/reloader_test.go` (CRY-WU-12). POAM-003. |
| IA-5(1) | Inherited | Customer | Password policy inherited from the federated IdP. |
| IA-5(2) | Planned | System | PKI cert lifecycle (webhook/mTLS certs) in P2. |
| IA-6 | Inherited | Customer | Authn-feedback obscuring inherited from the IdP login UI. |
| IA-7 | Planned | System | FIPS-140-3 validated module (GOFIPS140) established in P2. POAM-005. |
| IA-8 / IA-8(1)/(2)/(4) | Planned | System/Shared | Non-org-user authN scoping (likely N/A post-scoping); PIV-I/external-authenticator/profile acceptance via IdP federation in P3. |
| IA-11 | Planned | System | Re-authentication on privileged actions/session expiry in P3. |
| IA-12 / IA-12(2)/(3)/(5) | Inherited | Customer | Identity proofing, evidence handling/validation, and address confirmation inherited from the federated IdP/CSP. |

### 7.8 IR — Incident Response

**Allocation: Shared** ([CRM §IR](../CRM.md)). Detection, alerting rules, and Alertmanager routing for System
workloads are delivered in P9; the organizational IR plan, handling/reporting authority, and the receiving
SOC/SIEM are Customer. Policy/procedures/plan: [IR policy](../policies/IR-policy.md),
[IR procedures](../procedures/IR-procedures.md), [incident-response-plan.md](../plans/incident-response-plan.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| IR-1 | Planned | CSP | IR-1 policy authored ([IR-policy.md](../policies/IR-policy.md)); Planned pending P12. POAM-010. |
| IR-2 | Planned | CSP | IR training program in P12. |
| IR-3 / IR-3(2) | Planned | CSP | Tabletop/IR testing (P9/P12) and coordination with CP/CSP plans (P12). |
| IR-4 / IR-4(1) | Planned | Shared | Incident-handling workflow and automated alert-to-incident pipeline from alerting in P9. |
| IR-5 | Planned | Shared | Incident monitoring via metrics/alerts in P9. |
| IR-6 / IR-6(1) | Planned | CSP/Shared | US-CERT/CSP reporting workflow (P9/P12) + automated reporting integration (P9). |
| IR-7 / IR-7(1) | Planned | CSP/Shared | IR assistance/contacts (P12) + automation support via SIEM/runbooks (P9). |
| IR-8 | Planned | CSP | IR plan authored in P12 (the [incident-response-plan.md](../plans/incident-response-plan.md) artifact exists; the matrix keeps the row Planned pending the P12 program). POAM-010. |

### 7.9 MA — Maintenance

**Allocation: Shared** ([CRM §MA](../CRM.md)). The application upgrade/maintenance procedure is delivered via
operations runbooks; hardware/infrastructure maintenance is CSP-Inherited; the organizational maintenance
program and maintenance-personnel controls are Customer. Policy: [MA policy](../policies/MA-policy.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| MA-1 | Planned | CSP | MA-1 policy authored ([MA-policy.md](../policies/MA-policy.md)); Planned pending P12. POAM-010. |
| MA-2 | Planned | Shared | Maintenance via GitOps/rolling upgrade; procedure in P12. |
| MA-3 / MA-3(1)/(2)/(3) | Inherited | Customer | Physical maintenance tools, tool/media inspection, and unauthorized-removal prevention inherited from the CSP. |
| MA-4 | Planned | Shared | Remote maintenance over authenticated/TLS planes (P3); procedure in P12. |
| MA-5 | Inherited | Customer | Maintenance-personnel vetting inherited from CSP/operator. |
| MA-6 | Planned | Shared | Spares/support availability via container orchestration; procedure in P12. |

### 7.10 MP — Media Protection

**Allocation: Customer-Responsibility / CSP-Inherited** (System provides MP-1 policy only)
([CRM §MP](../CRM.md)). Kube-Policies handles no removable media. Policy: [MP policy](../policies/MP-policy.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| MP-1 | Planned | CSP | MP-1 policy authored ([MP-policy.md](../policies/MP-policy.md)); Planned pending P12. POAM-010. |
| MP-2 / MP-3 / MP-4 / MP-5 / MP-6 | Inherited | Customer | Physical media access, marking, storage, transport, and sanitization inherited from the CSP. |
| MP-7 | Planned | CSP | Removable-media use policy authored in P12. |

### 7.11 PE — Physical and Environmental Protection

**Allocation: CSP-Inherited (wholly)** ([CRM §PE](../CRM.md)). Kube-Policies operates no physical facilities,
power, fire suppression, or environmental controls; the **entire PE family** is inherited from the hosting
CSP's FedRAMP-authorized data centers. The customer documents the inheritance by citing the CSP's authorization
package and confirming scope via the CSP ATO/CRM (verified in P12). Policy: [PE policy](../policies/PE-policy.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| PE-1, PE-2, PE-3, PE-4, PE-5, PE-6, PE-6(1), PE-8, PE-9, PE-10, PE-11, PE-12, PE-13, PE-13(1), PE-13(2), PE-14, PE-15, PE-16, PE-17 | Inherited | Customer | Physical/environmental control fully inherited from the hosting CSP data center; verified via CSP ATO/CRM in P12. No System or Customer action implements these controls beyond documenting the inheritance. |

### 7.12 PL — Planning

**Allocation: System-Implemented** ([CRM §PL](../CRM.md)). The System authors this SSP, the PL-8 security
architecture (trust zones ZONE-EXT/ZONE-SYS in [system-facts.md](../system-facts.md)), the rules of behavior
(P12), and selects/tailors the FedRAMP Moderate baseline. Policy: [PL policy](../policies/PL-policy.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| PL-1 | Planned | CSP | PL-1 policy authored ([PL-policy.md](../policies/PL-policy.md)); Planned pending P12. POAM-010. |
| PL-2 | Partial | CSP | SSP skeleton established in P0 (this document, [SSP.md](SSP.md)); narratives finalized in P12 (this work unit). |
| PL-4 / PL-4(1) | Planned | CSP | Rules of behavior (incl. social-media/external-site usage restrictions) authored in P12. |
| PL-8 | Partial | System | Architecture/trust-zones (ZONE-EXT/ZONE-SYS) documented in [system-facts.md](../system-facts.md) + boundary diagram; finalized in this SSP P12. Evidence: `compliance_check.py` (inventory↔authorization-boundary consistency + doc-link gate) (CA-WU-01). |
| PL-10 | Implemented | CSP | FedRAMP Moderate baseline selected (this [control matrix](../control-matrix.csv)); reconcile vs the official OSCAL profile tracked in POAM-009. |
| PL-11 | Partial | CSP | Baseline tailoring (N/A, inherited) recorded in [control-matrix.md](../control-matrix.md); reconcile vs the official FedRAMP Rev5 Moderate OSCAL profile. POAM-009. |

### 7.13 PM — Program Management

**Allocation: Customer-Responsibility** ([CRM §PM](../CRM.md)). The organizational information-security
program is operator-owned; the System feeds it the component [inventory](../inventory.csv) (PM-5) and the
[POA&M](../poam.csv) (PM-4).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| PM-1 | Planned | CSP | Org infosec program plan (P12). |
| PM-2 | Planned | CSP | ISSO/senior-official role (TBD — assign) designated in P12. |
| PM-3 | Planned | CSP | Program resourcing in P12. |
| PM-4 | Partial | CSP | POA&M process established ([poam.csv](../poam.csv)); program-level tracking matured in P12. |
| PM-5 | Partial | CSP | System inventory established (AST-*) in [inventory.csv](../inventory.csv); org-wide inventory program in P12. |
| PM-6 | Planned | CSP | Security performance measures via ConMon metrics in P9/P12. |
| PM-7 / PM-9 / PM-10 / PM-11 | Planned | CSP | Enterprise architecture, org risk-management strategy, authorization/ATO process, and mission/business-process definition in P12. |

### 7.14 PS — Personnel Security

**Allocation: Customer-Responsibility** (System provides PS-1 policy only) ([CRM §PS](../CRM.md)). HR/org
screening, termination/transfer, and access agreements are operator-owned. Policy: [PS policy](../policies/PS-policy.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| PS-1 | Planned | CSP | PS-1 policy authored ([PS-policy.md](../policies/PS-policy.md)); Planned pending P12. POAM-010. |
| PS-2 | Planned | CSP | Position-risk designation in P12. |
| PS-3 | Inherited | Customer | Personnel screening inherited from the operator org; verified P12. |
| PS-4 / PS-5 / PS-6 / PS-7 / PS-8 / PS-9 | Planned | CSP | Termination/transfer procedures, access agreements, external-personnel security, sanctions process, and security position descriptions authored in P12. |

### 7.15 RA — Risk Assessment

**Allocation: Shared** ([CRM §RA](../CRM.md)). The System authors the FIPS-199 categorization (RA-2), the
canonical [STRIDE threat model](../threat-model.md) (RA-3) — per-`ICX-01..06` threat→control→POA&M tables —
and delivers vulnerability scanning (RA-5) configured to gate the build in P11; cluster/organizational RA and
risk-response decisions are Customer. Policy/procedures: [RA policy](../policies/RA-policy.md),
[RA procedures](../procedures/RA-procedures.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| RA-1 | Planned | CSP | RA-1 policy authored ([RA-policy.md](../policies/RA-policy.md)); Planned pending P12. POAM-010. |
| RA-2 | Implemented | CSP | FIPS-199 Moderate categorization completed in P0 ([FIPS-199.md](../categorization/FIPS-199.md)). |
| RA-3 | Partial | CSP | Grounded 12-dimension gap analysis (`.omc/research/fedramp-cis-gap-analysis.json`) serves as the initial risk assessment, supported by the canonical [STRIDE threat model](../threat-model.md) mapping every trust-boundary crossing to a mitigation/control/POA&M item; formal RA in P12. |
| RA-3(1) | Planned | System | Supply-chain risk assessment (SBOM/provenance) in P6. |
| RA-5 | Partial | System | Trivy fs/image/config (security-scan job) + govulncheck CONFIGURED/authored in P11 and aggregated by ci-gate ([`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml), [`monthly-vuln-scan.yml`](../../../.github/workflows/monthly-vuln-scan.yml), [vulnerability-management.md](../../security/vulnerability-management.md)); gitleaks + pnpm audit are independent required checks. Execution/enforcement pending first CI run + branch-protection enablement (no ATO) — Partial until evidenced. Evidence: security-scan job (Trivy fs/image GATE, CRITICAL/HIGH→fail) + govulncheck job, aggregated by ci-gate (SDL-WU-12). POAM-008. |
| RA-5(2) | Partial | System | Trivy DB auto-update on each CI/monthly scan run CONFIGURED/authored in P11; cadence documented in [vulnerability-management.md](../../security/vulnerability-management.md). Partial until evidenced. Evidence: security-scan job (Trivy GATE, DB refreshed per run) + [`monthly-vuln-scan.yml`](../../../.github/workflows/monthly-vuln-scan.yml) (SDL-WU-12). |
| RA-5(5) | Partial | System | Authenticated/credentialed DAST + coverage evidence CONFIGURED in P11; not yet executed (no live CI run). Partial until evidenced. Evidence: [`dast.yml`](../../../.github/workflows/dast.yml) (ZAP) + [`monthly-vuln-scan.yml`](../../../.github/workflows/monthly-vuln-scan.yml) (SDL-WU-13). |
| RA-7 | Partial | CSP | Risk response tracked via [POA&M](../poam.csv); closure across P1–P12. |

### 7.16 SA — System and Services Acquisition

**Allocation: Shared** ([CRM §SA](../CRM.md)). The System implements the secure SDLC (SA-3/SA-8/SA-15),
developer testing (SA-11), and supply-chain SBOM/provenance (SA-10); CI trustworthiness/branch-protection is
configured but pending first-run enforcement (no ATO), so those rows stay Partial. The SA-15/SA-11
threat-modeling expectation (per [`CONTRIBUTING.md`](../../../CONTRIBUTING.md) §"Security Review Process") is
realized by the canonical [STRIDE threat model](../threat-model.md), re-reviewed on significant architectural
change. Policy/procedures: [SA policy](../policies/SA-policy.md), [SA procedures](../procedures/SA-procedures.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| SA-1 | Implemented | System | SA-1 policy + procedures authored in P11 ([SA-policy.md](../policies/SA-policy.md), [SA-procedures.md](../procedures/SA-procedures.md)). Evidence: `compliance_check.py` doc-link/structure gate + docs markdown-link-check (SDL-WU-29). POAM-010. |
| SA-2 | Planned | CSP | Resource allocation for security in P12. |
| SA-3 | Partial | System | Secure-SDLC document + SSDF crosswalk CONFIGURED/authored in P11 ([secure-sdlc.md](../../security/secure-sdlc.md)); CI-gate jobs + branch-protection documented. Execution pending first CI run + branch-protection (no ATO) — Partial until evidenced. Evidence: ci-gate aggregation job (`.github/workflows/ci.yml`) + `compliance_check.py` doc-link gate (SDL-WU-28). |
| SA-4 / SA-4(1)/(2)/(10) | Planned | CSP/Shared | Acquisition/security-requirements language, functional-property + design/impl documentation, and approved-PIV-product use (via IdP federation) in P12/P3. |
| SA-4(9) | Partial | System | Ports/protocols/services documented in [system-facts.md](../system-facts.md) (ports table); finalized in this SSP P12. Evidence: `compliance_check.py` doc-link/structure gate over docs/compliance + docs markdown-link-check (CA-WU-01). |
| SA-5 | Partial | System | Engineering docs exist ([README.md](../../../README.md), [secure-sdlc.md](../../security/secure-sdlc.md), [testing.md](../../testing.md), [vulnerability-management.md](../../security/vulnerability-management.md)); full admin/security documentation completed P12. Evidence: `compliance_check.py` doc-link gate over docs/security + docs/compliance + docs markdown-link-check (SDL-WU-30). |
| SA-8 | Partial | System | Trust-zone/fail-closed design principles applied (documented in [system-facts.md](../system-facts.md)); applied across P0–P12. Evidence: `internal/admission/controller_behavior_test.go` (fail-closed validate path) + `internal/policymanager/router_authn_test.go` (deny-by-default) + `compliance_check.py` (CA-WU-01). |
| SA-9 | Planned | CSP | External-service agreements (CSP/IdP) in P12. |
| SA-9(2) | Partial | System | External connections ICX-01..06 enumerated in [system-facts.md](../system-facts.md); agreements in P12. Evidence: `compliance_check.py` doc-link/structure gate over docs/compliance + docs markdown-link-check (CA-WU-01). |
| SA-10 | Partial | System | Versioned build via CI/Helm ([`.github/workflows/release.yml`](../../../.github/workflows/release.yml)); provenance/SBOM integrity in P6. Evidence: reproducible-build job (`.github/workflows/ci.yml`) + `release.yml` (SLSA provenance/SBOM) (SDL-WU-18). |
| SA-11 | Partial | System | Unit-coverage floor (`cover-gate.sh`), SAST (gosec MEDIUM+ via lint job), fuzz-smoke, govulncheck, Trivy CONFIGURED/authored in P11 and aggregated by ci-gate ([`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)); tiers documented in [testing.md](../../testing.md). Partial until evidenced (no ATO). Evidence: unit-tests job (cover-gate.sh) + lint (gosec MEDIUM+) + fuzz-smoke + govulncheck jobs, aggregated by ci-gate (SDL-WU-04). |
| SA-11(1) | Partial | System | gosec MEDIUM+ gate CONFIGURED (lint job, aggregated by ci-gate); CodeQL security-extended (go+js/ts) CONFIGURED in [codeql.yml](../../../.github/workflows/codeql.yml) as an independent required check (SARIF/informational). Partial until evidenced. Evidence: lint job (gosec) aggregated by ci-gate + [`codeql.yml`](../../../.github/workflows/codeql.yml) (SDL-WU-06). POAM-008. |
| SA-11(8) | Partial | System | Go native fuzz targets (admission parser + Rego evaluator; 0 crashers locally) + fuzz-smoke job (ci-gate) + fuzz-nightly CONFIGURED/authored in P11; DAST ([`dast.yml`](../../../.github/workflows/dast.yml)) is a separate scheduled workflow. Partial until evidenced. Evidence: `internal/admission/controller_fuzz_test.go` + `internal/policy/engine_fuzz_test.go` via fuzz-smoke job (SDL-WU-05). |
| SA-15 | Partial | System | Pinned tools, CODEOWNERS, PR template, [secure-sdlc.md](../../security/secure-sdlc.md), and branch-protection policy ([branch-protection.md](../../security/branch-protection.md) + `.github/settings.yml`) CONFIGURED/authored in P11. Branch protection enablement + first CI run pending repo-admin action (no ATO) — Partial until evidenced. Evidence: actionlint job + reproducible-build job + `compliance_check.py` doc-link gate (SDL-WU-28). |
| SA-15(3) | Partial | System | Criticality-analysis section authored in [SA-policy.md](../policies/SA-policy.md) (P11); formal third-party criticality assessment remains P12. Evidence: `compliance_check.py` doc-link/structure gate + docs markdown-link-check (SDL-WU-29). |
| SA-22 | Implemented | System | Toolchain pinned to `go1.25.10` in `go.mod`; govulncheck gate confirms 0 reachable stdlib CVEs (previous ~26 CVEs from go1.25.0 remediated); no EOL/unsupported stdlib in use. Evidence: govulncheck job (0-reachable-vulns gate, [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)) + go.mod toolchain pin (SDL-WU-19). |

### 7.17 SC — System and Communications Protection

**Allocation: Shared** ([CRM §SC](../CRM.md)). The webhook serves TLS 1.3 (bright spot); boundary protection
(SC-7) ships as default-deny + least-privilege-allow-list NetworkPolicies that **require a NetworkPolicy-enforcing
CNI** (Calico/Cilium/Antrea) — inert on kindnet, and live e2e enforcement is designed but not yet run, so those
rows are **Implemented (Helm) — requires enforcing CNI**, not Implemented. FIPS-validated cryptography (SC-13),
PKI/key management (SC-12/SC-17), and at-rest protection (SC-28) are Planned (P2). Policy/procedures and the
allowed-flow architecture: [SC policy](../policies/SC-policy.md), [SC procedures](../procedures/SC-procedures.md),
[network-architecture.md](../network-architecture.md) (SC-7/CA-3 + SC-5 DoS protections).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| SC-1 | Planned | CSP | SC-1 policy authored ([SC-policy.md](../policies/SC-policy.md)); Planned pending P12. POAM-010. |
| SC-2 | Partial | System | Dashboard BFF separates UI from API (`cmd/dashboard/proxy.go`); management/enforcement-plane split formalized in P3/P4. Evidence: `cmd/dashboard/proxy_audit_test.go` + `cmd/dashboard/auth_test.go` (IAM-WU-01). |
| SC-4 | Planned | System | readOnlyRootFilesystem + non-root reduce residual data (`charts/kube-policies/values.yaml`); formalized in P5. |
| SC-5 | Partial | System | Per-replica rate limiting (50 rps/burst 100), max-in-flight + SSE caps (429), 3 MiB body cap (413), `kube_policies_http_rate_limited_total` metric, bounded MaxConcurrentReconciles (`internal/middleware/ratelimit.go`); ResourceQuota/LimitRange ship OFF by default. Evidence: `ratelimit_test.go` + `internal/policymanager/router_ratelimit_test.go` (NET-WU-19). POAM-027. |
| SC-6 | Partial | System | Replicas + leader election aid availability (`cmd/admission-webhook/main.go`); PDB/anti-affinity/limits in P8. Evidence: `test/integration/leader_election_test.go` + `test/e2e/state_recovery_test.go` (RES-WU-03). |
| SC-7 | Implemented (Helm) — requires enforcing CNI | System | Default-deny + least-privilege allow-list NetworkPolicies ship (chart + static base: `charts/kube-policies/templates/networkpolicy-*.yaml`, `deployments/kubernetes/base/networkpolicy.yaml`). REQUIRES a NetworkPolicy-enforcing CNI; inert on kindnet; live e2e enforcement designed, not yet run. Every allowed flow mapped to its template in [network-architecture.md](../network-architecture.md). Evidence: network-posture-gate (`test/policy/network_posture.rego` conftest; default-deny-removal keystone regression) (NET-WU-17). POAM-007. |
| SC-7(3) | Implemented (Helm) — requires enforcing CNI | System | Per-port managed access points (apiserver→:8443, scraper→metrics, ingress→:8090, webhook/dashboard→:8080) scoped via NetworkPolicy (`networkpolicy-ingress-*.yaml`). Requires enforcing CNI. Evidence: network-posture-gate (per-port ingress assertions) (NET-WU-18). |
| SC-7(4) | Implemented (Helm) — requires enforcing CNI | System | Scoped deny-by-default egress (kube-dns:53 + operator-set apiserver CIDRs + in-namespace hops only; no 0.0.0.0/0) in `networkpolicy-egress-*.yaml`. Requires enforcing CNI. Evidence: network-posture-gate (egress allow-list + no-0.0.0.0/0 assertions) (NET-WU-18). |
| SC-7(5) | Implemented (Helm) — requires enforcing CNI | System | `podSelector:{}` default-deny ingress+egress baseline + explicit allow-list (`networkpolicy-default-deny.yaml`); apiserver-egress/webhook-ingress render fail-closed when CIDRs empty. Requires enforcing CNI. Evidence: network-posture-gate (default-deny-removal keystone must re-fail) (NET-WU-17). POAM-007. |
| SC-7(7) | Implemented (Helm) — requires enforcing CNI | System | Enumerated egress (no 0.0.0.0/0) prevents split-tunnel/exfil to arbitrary destinations (`networkpolicy-egress-*.yaml`). Requires enforcing CNI. Evidence: network-posture-gate (no-0.0.0.0/0 egress assertion) (NET-WU-18). |
| SC-8 | Partial | System | Webhook TLS 1.3 (ICX-01); P2/P3 added TLS 1.3 on the policy-manager API and verified HTTPS (RootCAs, no InsecureSkipVerify) for the webhook→PM decisions channel (`cmd/admission-webhook/main.go`, `internal/config/tls.go`, `internal/admission/decision_publisher.go`). Dashboard in-pod TLS + metrics-plane authn remain config-gated/off (POAM-004 residual). Evidence: `tls_test.go` + `tls_conformance_test.go` + `decision_publisher_test.go` (CRY-WU-12). |
| SC-8(1) | Partial | System | Webhook TLS 1.3 cryptographic protection (ICX-01) with optional apiserver mTLS (`--require-client-cert` default true at binary; chart default false for dev) + optional policy-manager API mTLS (`cmd/admission-webhook/main.go`, `internal/config/tls.go`). Config-gated items off by default. Evidence: `tls_test.go` + `mtls_test.go` + `client_mtls_test.go` (CRY-WU-12). POAM-003. |
| SC-10 | Planned | System | Session/idle disconnect on the management plane in P3. |
| SC-12 / SC-12(2)/(3) | Planned | System | Cert/secret material exists (`charts/kube-policies/templates/admission-webhook-tls.yaml`) but no lifecycle; PKI key mgmt + rotation, symmetric (audit HMAC) and asymmetric (TLS/mTLS) key mgmt in P2. POAM-005. |
| SC-13 | Planned | System | No FIPS-validated module today; FIPS-140-3 (GOFIPS140) crypto in P2. POAM-005. |
| SC-15 | Not-Applicable | System | No collaborative-computing (mic/camera) components. |
| SC-17 | Planned | System | PKI certificate issuance/management (cert-manager or equivalent) in P2. POAM-005. |
| SC-18 | Planned | System | Svelte SPA mobile code (`web/`); CSP headers + integrity controls in P5. |
| SC-20 / SC-21 / SC-22 | Inherited | Customer | Authoritative/recursive DNS and name-resolution architecture inherited from cluster CoreDNS/CSP; egress scoped in P4. |
| SC-23 | Planned | System | TLS session authenticity on all planes + token binding in P3. |
| SC-28 | Planned | System | CRDs in etcd; etcd encryption-at-rest verification + app at-rest crypto in P2. POAM-005. |
| SC-28(1) | Planned | Shared | Encryption-at-rest via CSP/etcd KMS + FIPS module; verified in P2. POAM-005. |
| SC-39 | Partial | System | Container isolation (distroless, non-root, dropped caps) via `charts/kube-policies/values.yaml`; restricted PSS in P5. Evidence: manifest-hardening-gate (`restricted-pss.rego` conftest) + `hardening_test.yaml` (CFG-WU-12). |

### 7.18 SI — System and Information Integrity

**Allocation: Shared** ([CRM §SI](../CRM.md)). Flaw remediation (SI-2) of reachable stdlib CVEs is evidenced
locally (toolchain pin → govulncheck 0 reachable); information-input validation (SI-10) in the admission engine
is locked by adversarial-corpus + fuzz tests. Image scanning/signature verification (SI-3/SI-7) is P6, IDS-grade
monitoring/SIEM (SI-4) is P9, and the broader SLA-tracked remediation program is pending first CI run (no ATO).
Policy/procedures: [SI policy](../policies/SI-policy.md), [SI procedures](../procedures/SI-procedures.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| SI-1 | Planned | CSP | SI-1 policy authored ([SI-policy.md](../policies/SI-policy.md)); Planned pending P12. POAM-010. |
| SI-2 | Implemented | System | Reachable stdlib CVEs remediated by pinning the toolchain to `go1.25.10` (govulncheck 0 reachable, verified locally); remediation SLA 30/90/180 days documented in [SECURITY.md](../../../SECURITY.md). Implemented status is scoped to this evidenced local remediation; the broader SLA program (Dependabot, base-image-refresh) is configured but operationally pending first CI run (no ATO; tracked under SA-11/RA-5). Artifacts: `.github/workflows/ci.yml`, `go.mod`, `.github/dependabot.yml`, [`base-image-refresh.yml`](../../../.github/workflows/base-image-refresh.yml). Evidence: govulncheck job (0-reachable gate) + security-scan (Trivy GATE) in `.github/workflows/ci.yml` (SDL-WU-19). POAM-008. |
| SI-2(2) | Partial | System | Automated POA&M aging/SLA-breach tracking + alerting CONFIGURED/authored in P11 ([`poam-aging.yml`](../../../.github/workflows/poam-aging.yml)). Partial until evidenced (no ATO). Evidence: `poam-aging.yml` (SLA-breach gate over poam.csv) + `compliance_check.py` (poam.csv severity/scheduled_completion gate) (SDL-WU-22). POAM-008. |
| SI-3 | Planned | System | Image scanning (Trivy) + signature-verification admission in P6/P10. |
| SI-4 | Partial | System | Prometheus collector + Alertmanager exist (PoC) via `internal/metrics/collector.go`; IDS-grade detection/SIEM in P9. Evidence: `collector_test.go` + monitoring-rules job (promtool check/test over alert rules) (IRM-WU-14). |
| SI-4(2)/(4)/(5) | Planned | Shared | Real-time SIEM analysis, inbound/outbound traffic monitoring (NetworkPolicy logs + SIEM), and system-generated security alerts packaged as PrometheusRule in P9. |
| SI-5 | Planned | CSP | CISA/vendor advisory intake process in P11/P12. |
| SI-6 | Planned | System | Self-test/function verification of security controls in P11. |
| SI-7 / SI-7(1) | Planned | System | Image-signature verification + SBOM/provenance integrity, and integrity checks at admission (cosign verify), in P6/P10. POAM-006. |
| SI-8 | Not-Applicable | System | No email/messaging components in the boundary. |
| SI-10 | Implemented | System | Config + admission input validation present; adversarial-input corpus (`controller_validation_test.go`) + Go native fuzz tests (admission parser + Rego evaluator) added in P11; fail-closed behaviour locked by tests. Artifacts: `internal/config/config.go`, `internal/admission/controller_validation_test.go`, `internal/admission/controller_fuzz_test.go`, `internal/policy/engine_fuzz_test.go`. Evidence: `controller_validation_test.go` + `controller_fuzz_test.go` + `engine_fuzz_test.go` via fuzz-smoke job (SDL-WU-05). |
| SI-11 | Partial | System | `gin.Recovery()` handles panics (`internal/policymanager/router.go`); structured error handling / no-leak review in P11. Evidence: `controller_behavior_test.go` (TestValidateHandler_FailSafeOnEngineError: deny + no panic) + `auth_middleware_test.go` (error paths) (SDL-WU-07). |
| SI-12 | Planned | Shared | Audit/data retention policy defined in P7; long-term in P9. |
| SI-16 | Partial | System | Go memory safety + non-root/read-only FS; seccomp RuntimeDefault (`charts/kube-policies/values.yaml`). Evidence: manifest-hardening-gate (`restricted-pss.rego`: readOnlyRootFilesystem + seccompProfile RuntimeDefault) + `hardening_test.yaml` (CFG-WU-12). |

### 7.19 SR — Supply Chain Risk Management

**Allocation: Shared** ([CRM §SR](../CRM.md)). SBOM generation and SLSA provenance scaffolding ship via the
release workflow and an admission-time provenance rule, with distroless base images reducing supply-chain
surface; full signing/verification (cosign), provenance attestation, and the SCRM plan are P6, and the registry
+ admission-time verification policy are Customer. Policy: [SR policy](../policies/SR-policy.md).

| Control | Status | Resp. | Implementation narrative / rationale |
|---|---|---|---|
| SR-1 | Planned | CSP | SR-1 policy authored ([SR-policy.md](../policies/SR-policy.md)); Planned pending P12. POAM-010. |
| SR-2 / SR-2(1) | Planned | CSP | SCRM plan authored (P6/P12) + SCRM team designation (P12). |
| SR-3 | Partial | System | SBOM generation exists but unverified at consumption ([`.github/workflows/release.yml`](../../../.github/workflows/release.yml)); provenance + verification controls in P6. Evidence: reproducible-build job (`.github/workflows/ci.yml`) + `release.yml` (SBOM/SLSA provenance) + `internal/policy/image_provenance_test.go` (admission-time provenance rule) (SDL-WU-18). POAM-006. |
| SR-4 | Planned | System | SLSA provenance attestation (build-by-digest) added in P6 ([`.github/workflows/release.yml`](../../../.github/workflows/release.yml)). POAM-006. |
| SR-5 | Planned | System | Pinned dependencies/actions + acquisition controls in P1/P6. |
| SR-6 | Planned | CSP | Supplier/dependency review in P6. |
| SR-8 | Planned | CSP | Supplier notification agreements in P12. |
| SR-9 | Planned | System | Image digest pinning + signature verification provide tamper detection in P6. POAM-006. |
| SR-10 | Planned | System | Component inspection via SBOM/scan/verify in P6. |
| SR-11 / SR-11(2) | Planned | System | Cosign signature verification establishes authenticity; config control for component repair via GitOps, in P6. POAM-006 (SR-11). |
| SR-11(1) | Planned | CSP | Anti-counterfeit awareness training in P12. |
| SR-12 | Planned | Shared | Component/image disposal procedure in P12. |

## 8 Acronyms

| Acronym | Expansion |
|---|---|
| AO | Authorizing Official |
| AST | Asset (canonical asset ID prefix) |
| ATO | Authorization to Operate |
| BFF | Backend-for-Frontend |
| CRD | CustomResourceDefinition |
| CRM | Customer Responsibility Matrix |
| CSP | Cloud Service Provider |
| FedRAMP | Federal Risk and Authorization Management Program |
| FIPS | Federal Information Processing Standard |
| FISMA | Federal Information Security Modernization Act |
| ICX | Interconnection (canonical interconnection ID prefix) |
| ISSO | Information System Security Officer |
| KP | Kube-Policies (system abbreviation) |
| mTLS | Mutual Transport Layer Security |
| NIST | National Institute of Standards and Technology |
| OIDC | OpenID Connect |
| OPA | Open Policy Agent |
| PoC | Proof of Concept |
| POA&M | Plan of Action and Milestones |
| PPS | Ports, Protocols & Services |
| RBAC | Role-Based Access Control |
| SA | ServiceAccount (Kubernetes) |
| SAR | Security Assessment Report |
| SP | Special Publication (NIST) |
| SPA | Single-Page Application |
| SSP | System Security Plan |
| TLS | Transport Layer Security |
| ZONE-EXT | External trust zone (outside the authorization boundary) |
| ZONE-SYS | System trust zone (inside the authorization boundary) |
