---
title: "Security Architecture (PL-8) — Kube-Policies (KP)"
control_family: "PL-8 — Security and Privacy Architectures"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Security Architecture — Kube-Policies (KP)

This document is the **PL-8 (Security and Privacy Architectures)** description for the
Kube-Policies system (KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5**
(FedRAMP **Moderate** baseline). It describes the defense-in-depth architecture, identifies
where each layer is enforced, and is kept consistent with the
[authorization-boundary diagram](diagrams/authorization-boundary.md) and the
[data-flow diagram](diagrams/data-flow.md). It is governed by the
[Planning Policy (PL-1/PL-2)](policies/PL-policy.md) and referenced from the
[SSP](ssp/SSP.md) and the [CRM](CRM.md) (PL — Planning).

All component names, asset IDs (`AST-*`), ports, trust zones (`ZONE-EXT`/`ZONE-SYS`), and
interconnections (`ICX-01..06`) are used verbatim from the
[system facts sheet](system-facts.md).

**Annual review.** This architecture description is reviewed at least **annually** (next
review **2027-05-29**) and whenever the architecture, authorization boundary, components, or
interconnections materially change.

> **Honesty note.** KP is a Proof-of-Concept being driven to assessment readiness. This
> document describes the **as-built** architecture and explicitly separates current posture
> from target posture. Where prior material (notably `PROJECT_SUMMARY.md`) overstated the
> security architecture, those claims are reconciled and scoped in §5 and are being corrected
> under work unit **DOC-WU-30**. Open weaknesses are tracked in the [POA&M](poam.csv) and
> remediated across phases P0–P12 (`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`).

## 1 Architectural intent

KP implements a **defense-in-depth** strategy across four layers, each enforced at a
distinct asset and trust position:

1. **Admission control** at the webhook (`AST-WH`) — the enforcement plane that intercepts
   and adjudicates `AdmissionReview` requests from the kube-apiserver.
2. **Policy management** at the policy-manager (`AST-PM`) — the control plane that owns the
   `Policy`/`PolicyException` CRDs, reconciles them, and records admission decisions.
3. **Read-only visibility** at the dashboard (`AST-DB`/`AST-SPA`) — the presentation plane,
   read-only by default (`ALLOW_WRITES=false`), that surfaces policy state and the decision
   feed without granting write authority.
4. **Monitoring** — Prometheus-scrapable metrics exposed by every component
   (`:9090`/`:9091`/`:9092`), providing operational signal for detection and accountability.

The shared policy-evaluation core (`AST-OPA`, OPA/Rego) is embedded as a library inside both
`AST-WH` and `AST-PM`, so the same compiled rules govern both enforcement and management.

## 2 Trust zones and boundary

Two trust zones apply, consistent with the
[authorization-boundary diagram](diagrams/authorization-boundary.md):

- **`ZONE-EXT`** (outside the boundary): kube-apiserver, Prometheus scraper, cluster
  operators/users, and the hosting CSP control plane and infrastructure.
- **`ZONE-SYS`** (inside the boundary): the `kube-policies-system` namespace workloads
  (`AST-WH`, `AST-PM`, `AST-DB`/`AST-SPA`, embedded `AST-OPA`) and the namespaced CRDs
  (`AST-CRD-POL`, `AST-CRD-EXC`).

Platform controls underneath KP — physical/environmental (PE), media protection (MP/MA), and
the host/network platform underpinning SC-7 — are **Inherited** from the CSP and are not
implemented inside the KP boundary; the responsible-party split is recorded in the
[control matrix](control-matrix.csv) and the [CRM](CRM.md).

## 3 Defense-in-depth layers

### 3.1 Layer 1 — Admission control at `AST-WH` (enforcement plane)

`AST-WH` is the validating/mutating admission webhook. The kube-apiserver calls it over
`ICX-01` (`POST /validate`, `/mutate` on `8443/tcp`) with an `AdmissionReview`; the webhook
evaluates the object against the compiled Rego policies via the embedded `AST-OPA` and returns
an allow/deny (plus mutations) on the same connection.

- **Current strengths (bright spots).**
  - `ICX-01` is the **only transport-encrypted** flow today: `8443/tcp` is pinned to
    **TLS 1.3** (`internal/config`).
  - Admission **fails closed by default**: `failure_mode` is validated to
    `fail-open|fail-closed` and the shipped default is **fail-closed**, so a webhook outage
    denies rather than silently admits at the enforced boundary.
- **Current residual gaps (target posture).**
  - TLS on `8443` is **server-auth only**; the webhook does not yet mutually authenticate
    the apiserver. apiserver **mTLS** is a phase **P3** target.
  - Enforcement operates on the submitted object; deeper `spec.template.spec` enforcement
    completeness is tracked separately (policy-library work, P10).

### 3.2 Layer 2 — Policy management at `AST-PM` (control plane)

`AST-PM` is the policy control plane. It exposes a REST API (`/api/v1` on `8080/tcp`),
reconciles the `Policy` (`AST-CRD-POL`) and `PolicyException` (`AST-CRD-EXC`) CRDs against the
kube-apiserver over `ICX-06` (in-cluster TLS using the ServiceAccount token, with a
leader-election Lease), and receives published admission decision records from `AST-WH` over
`ICX-02` (`POST /api/v1/decisions/internal`).

- **Current strengths.**
  - Owns the authoritative policy/exception data model; reconciliation and leader election
    are in place (single-writer semantics via Lease).
  - `ICX-06` rides the platform's in-cluster TLS and SA token.
- **Current residual gaps (target posture).**
  - The REST API on `8080` is **HTTP and unauthenticated**; TLS 1.3 + OIDC/authZ are phase
    **P2/P3** targets.
  - `ICX-02` decision publish is **cleartext HTTP protected only by a static bearer token**;
    TLS + an audience-bound token is a phase **P3/P4** target.
  - The reconcile ServiceAccount is not yet least-privilege; RBAC scoping is a phase **P3**
    target.

### 3.3 Layer 3 — Read-only visibility at `AST-DB`/`AST-SPA` (presentation plane)

`AST-DB` serves the embedded Svelte SPA (`AST-SPA`), a BFF `/api`, and a reverse proxy
`/api/v1`→`AST-PM:8080` on `8090/tcp`. Operators/users reach it over `ICX-05`; it pulls policy
data and the decision feed from `AST-PM` over `ICX-04`.

- **Current strengths.**
  - **Read-only by default**: writes are gated behind `ALLOW_WRITES=true`
    (`cmd/dashboard/proxy.go`), so the default presentation plane cannot mutate policy and
    limits integrity exposure.
  - Pod hardening is already applied: `runAsNonRoot`, `allowPrivilegeEscalation:false`, and
    `readOnlyRootFilesystem` (`charts/.../dashboard-deployment.yaml`); the image uses a
    minimal base.
- **Current residual gaps (target posture).**
  - `ICX-05` is **cleartext HTTP with no user authentication**; TLS + OIDC login is a phase
    **P3** target.
  - `ICX-04` (dashboard→`AST-PM`) is **cleartext HTTP**; TLS is a phase **P4** target.

### 3.4 Layer 4 — Monitoring (operational signal)

Every component exposes Prometheus metrics, scraped by the external Prometheus over `ICX-03`:
`AST-WH:9090`, `AST-PM:9091`, `AST-DB:9092`.

- **Current strengths.** Uniform metrics exposition across all three services supports
  operational monitoring and is a foundation for AU/SI detection work.
- **Current residual gaps (target posture).** All metrics planes are **unauthenticated
  cleartext HTTP** and, absent a NetworkPolicy, reachable by any in-cluster peer; TLS + authn
  is a phase **P3** target, and detection/alerting/SIEM maturation is phase **P9**.

## 4 Layer-to-asset / interconnection map

| Defense layer | Enforced at | Interconnections | Current posture | Target (phase) |
|---|---|---|---|---|
| Admission control | `AST-WH` (`:8443`) + embedded `AST-OPA` | `ICX-01` | TLS 1.3 server-auth; **fail-closed default** | apiserver mTLS (P3) |
| Policy management | `AST-PM` (`:8080`) + `AST-CRD-POL`/`AST-CRD-EXC` | `ICX-02`, `ICX-06` | HTTP REST (unauth); CRD reconcile over in-cluster TLS; `ICX-02` static bearer | TLS + OIDC/authZ (P2/P3); audience-bound token (P3/P4); least-priv SA (P3) |
| Read-only visibility | `AST-DB`/`AST-SPA` (`:8090`) | `ICX-04`, `ICX-05` | HTTP, **read-only by default** (`ALLOW_WRITES`); pod hardening present | TLS + OIDC (P3); internal TLS (P4) |
| Monitoring | `:9090`/`:9091`/`:9092` (all components) | `ICX-03` | Unauthenticated cleartext HTTP | TLS + authn (P3); detection/SIEM (P9) |

This mapping is consistent with the boundary crossings shown in the
[authorization-boundary diagram](diagrams/authorization-boundary.md) (bold edges `ICX-01`,
`ICX-03`, `ICX-05`, `ICX-06`) and the runtime sequence in the
[data-flow diagram](diagrams/data-flow.md). The full per-interconnection sensitivity and
protection register is the [interconnection register](interconnections.md).

## 5 Reconciliation of aspirational claims (DOC-WU-30)

`PROJECT_SUMMARY.md` describes a target/aspirational architecture that overstates the
as-built PoC. The following claims are **scoped to documented reality**. These corrections are
tracked under work unit **DOC-WU-30**; the underlying capabilities are real *targets* mapped to
remediation phases, not current implementations.

| `PROJECT_SUMMARY.md` claim | Documented reality (as-built) | Disposition / phase |
|---|---|---|
| "mTLS for all inter-service communication" / "Zero Trust" | Only `ICX-01` is encrypted (TLS 1.3, **server-auth only**). `ICX-02`/`ICX-04`/`ICX-05` and all metrics planes are cleartext HTTP; most are unauthenticated. | Aspirational → mTLS/OIDC are **P3** (and P4); not yet implemented. |
| "AES-256 encryption at rest" | KP stores no data at rest of its own; CRD/etcd storage is the CSP's and **Inherited**. KP does not implement at-rest encryption. | Scope to Inherited (CSP); not a KP-implemented control. |
| "Tamper-evident audit trails with digital signatures" | Audit backend is validated to `file|stdout` and (in the PoC) writes to `emptyDir`; **no signing and no tamper-evidence** today. | Aspirational → audit durability/integrity is **P7**. |
| "High availability / multi-zone / automatic failover" | `AST-PM` uses leader election (single-writer); no documented multi-zone HA or failover design. | Aspirational → contingency/availability is **P8**. |
| "Enterprise SSO / RBAC / OIDC login" | No user authentication on any plane today; dashboard is unauthenticated (read-only by default). | Aspirational → OIDC/authZ is **P3**. |
| "Sub-millisecond evaluation / thousands of req/s / horizontal scaling" | Unverified performance marketing; no benchmark evidence in the boundary artifacts. | Out of scope for PL-8; treat as unsubstantiated until measured. |
| "Automated container/dependency scanning, signing, provenance; trustworthy CI" | CI is currently untrustworthy (a known foundational gap); no signing/provenance in place. | Aspirational → supply-chain integrity is **P6** (CI baseline **P1**). |
| "FIPS / encryption everywhere" | **No validated FIPS-140-3 cryptographic module**; TLS 1.3 is pinned only on `AST-WH:8443`. | Aspirational → cryptographic/FIPS foundation is **P2**. |
| Compliance with "NIST CSF 2.0, PCI DSS v4.0, SOX, HIPAA" | KP targets **FIPS-199 Moderate / NIST SP 800-53 Rev 5 (FedRAMP Moderate)** only; other framework claims are unsubstantiated. | Scope to the single targeted baseline; drop the rest. |

**Genuine current bright spots** (not aspirational): TLS 1.3 pinned on `AST-WH:8443`;
**fail-closed** admission default; dashboard **read-only by default**; dashboard pod hardening
(`runAsNonRoot`, `allowPrivilegeEscalation:false`, `readOnlyRootFilesystem`); leader election in
`AST-PM`; minimal/distroless image bases.

## 6 Residual risk and remediation

The architecture's principal residual risks are the unauthenticated/cleartext internal and
external planes (`ICX-02`/`ICX-03`/`ICX-04`/`ICX-05`), the absence of mutual authentication on
`ICX-01`, the lack of a validated FIPS module, audit durability/integrity, and untrustworthy
CI. Each is recorded in the [POA&M](poam.csv), mapped to a control in the
[control matrix](control-matrix.csv), and scheduled in a remediation phase (P1–P12 per
`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`). This document will be updated as those
phases land so that the "current posture" columns above remain accurate.

## 7 References

- [Authorization Boundary Diagram](diagrams/authorization-boundary.md)
- [Data Flow Diagram](diagrams/data-flow.md)
- [Network Boundary & Segmentation Architecture (SC-7/CA-3)](network-architecture.md) — every allowed flow mapped to its NetworkPolicy template
- [Interconnection Register](interconnections.md) (`ICX-01..06`)
- [System Security Plan (SSP)](ssp/SSP.md) · [Ports, Protocols & Services](ssp/ports-protocols-services.md)
- [Planning Policy (PL-1/PL-2)](policies/PL-policy.md)
- [Customer Responsibility Matrix (CRM)](CRM.md)
- [Control Matrix](control-matrix.csv) · [POA&M](poam.csv) · [Inventory](inventory.csv)
- [System Facts Sheet](system-facts.md) · [FIPS-199 Categorization](categorization/FIPS-199.md)
- NIST SP 800-53 Rev 5 (PL-8, SC-7, SC-8, SC-13, AC, AU, SI); FedRAMP Moderate baseline; FIPS-199.
