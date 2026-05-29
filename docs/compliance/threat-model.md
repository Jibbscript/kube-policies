---
title: "System Threat Model (STRIDE) — Kube-Policies (KP)"
control_family: "RA / SA — Risk Assessment & System Development"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# System Threat Model — Kube-Policies (KP)

This is the **canonical system threat model** for the Kube-Policies (KP) system, categorized
**FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate** baseline). It
realizes the **Threat Modeling** activity referenced in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) §"Security Review Process" — *"Significant
architectural changes undergo threat modeling"* — and serves as the threat-model artifact for
**RA-3 (Risk Assessment)** and **SA-15 / SA-11 (developer testing and evaluation)**.

It is driven entirely by the canonical facts: component names, asset IDs (`AST-*`), ports,
trust zones (`ZONE-EXT`/`ZONE-SYS`), and interconnections (`ICX-01..06`) are used **verbatim**
from the [System Facts Sheet](system-facts.md). The trust-boundary crossings analyzed below
are exactly the boundary crossings drawn in the [Data Flow Diagram](diagrams/data-flow.md)
(`ICX-01..06`) and the [Authorization Boundary Diagram](diagrams/authorization-boundary.md).

It is referenced from the [SSP](ssp/SSP.md) (§7.16 RA, §7.17 SA), the Risk-Assessment
procedures in the [CRM](CRM.md) (RA — Risk Assessment), the
[Security Architecture (PL-8)](security-architecture.md), and the [SAP](assessment/SAP.md).
The thin pointer at [`../security/threat-model.md`](../security/threat-model.md) resolves to
this document.

**Annual review.** This threat model is reviewed at least **annually** (next review
**2027-05-29**) and whenever the architecture, the authorization boundary, an interconnection
(`ICX-01..06`), or the policy-enforcement surface materially changes — consistent with the
"significant architectural changes undergo threat modeling" requirement in `CONTRIBUTING.md`.

> **Honesty note.** KP is an as-built Proof-of-Concept being driven to assessment readiness.
> Most threats below are **unmitigated or only partially mitigated today**; each such threat is
> tied to a [POA&M](poam.csv) item and a remediation phase (P1–P12,
> `.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`). A small set of genuine bright spots
> (TLS 1.3 on `AST-WH:8443`, fail-closed admission default, dashboard read-only-by-default,
> pod hardening, leader election) are called out where they actually reduce risk. Nothing here
> should be read as a claim that the system is currently secure.

---

## 1. Scope, methodology, and conventions

**Scope.** The assessed surface is exactly the authorization boundary: the In-Boundary assets
in `ZONE-SYS` (the `kube-policies-system` namespace) — `AST-WH`, `AST-PM`, `AST-DB`/`AST-SPA`,
embedded `AST-OPA`, and the namespaced CRDs `AST-CRD-POL`/`AST-CRD-EXC` — together with the six
trust-boundary crossings `ICX-01..06`. External actors (`ZONE-EXT`: kube-apiserver, Prometheus,
operators/users, the CSP platform) are modeled as threat sources and trust anchors but are not
themselves in scope for control implementation.

**Methodology.** **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, Denial
of service, Elevation of privilege) applied per **trust-boundary crossing**, organized by the
three primary components requested:

- **§3 `AST-WH`** — admission-webhook (`:8443` `/validate`,`/mutate`; `:9090` metrics):
  crossings `ICX-01`, `ICX-02` (originating), `ICX-03` (`:9090`).
- **§4 `AST-PM`** — policy-manager REST API + CRD reconcile (`:8080`; `:9091` metrics):
  crossings `ICX-02` (terminating), `ICX-04` (terminating), `ICX-06`, `ICX-03` (`:9091`).
- **§5 `AST-DB`** — dashboard BFF write-gating (`ALLOW_WRITES`) (`:8090`; `:9092` metrics):
  crossings `ICX-05`, `ICX-04` (originating), `ICX-03` (`:9092`).

**Mapping rule.** Every threat row maps **threat → mitigation → control ID → POA&M id**. Where
a threat is **already mitigated** (a bright spot), the POA&M column is `—` (none open). Where a
threat is **open / unmitigated or partial**, the POA&M column carries the responsible
[`poam.csv`](poam.csv) id and the remediation phase, so the threat model and the POA&M stay
reconciled. Control IDs are NIST SP 800-53 Rev 5 controls as tracked in the
[control matrix](control-matrix.csv).

**Trust-boundary crossings (from the [Data Flow Diagram](diagrams/data-flow.md)).**

| ICX | Crossing | Component focus | Current transport (facts sheet) |
|---|---|---|---|
| `ICX-01` | kube-apiserver (`ZONE-EXT`) → `AST-WH:8443` | §3 AST-WH | TLS 1.3, **server-auth only** |
| `ICX-02` | `AST-WH` → `AST-PM:8080` `/api/v1/decisions/internal` | §3/§4 | **HTTP + static bearer token** |
| `ICX-03` | Prometheus (`ZONE-EXT`) → `:9090`/`:9091`/`:9092` | §3/§4/§5 | **HTTP, unauthenticated** |
| `ICX-04` | `AST-DB` → `AST-PM:8080` (`/api/v1`, decisions stream) | §4/§5 | **HTTP** |
| `ICX-05` | Operators/users (`ZONE-EXT`) → `AST-DB:8090` | §5 | **HTTP, no user authn** (write-gated by `ALLOW_WRITES`) |
| `ICX-06` | `AST-PM` ↔ kube-apiserver (`ZONE-EXT`) | §4 | kubeconfig/SA token (in-cluster TLS) |

---

## 2. Adversaries, assets, and trust assumptions

**Threat actors.**

- **TA-1 In-cluster pod (untrusted tenant/compromised workload)** — any pod that can reach a
  `ZONE-SYS` listener. Absent a NetworkPolicy (POAM-007), this is the dominant adversary: it can
  reach `:8443`, `:8080`, `:8090`, and all metrics ports directly.
- **TA-2 Unauthorized cluster user/operator** — a human with network reach to `AST-DB:8090` or
  `AST-PM:8080` but no legitimate KP authorization (there is no authN today).
- **TA-3 Malicious policy author / CRD editor** — a principal with Kubernetes RBAC to create or
  edit `Policy`/`PolicyException` CRDs (`AST-CRD-POL`/`AST-CRD-EXC`).
- **TA-4 Network/path adversary (in-cluster)** — an entity able to observe or interpose on
  cleartext in-cluster traffic (`ICX-02`/`ICX-03`/`ICX-04`/`ICX-05`).
- **TA-5 Supply-chain adversary** — an entity able to influence the build/release pipeline,
  dependencies, base images, or unsigned artifacts.
- **TA-6 Compromised node / privileged platform actor** — root on a node hosting KP pods (can
  reach `emptyDir`-backed audit, in-memory secrets).

**Primary assets** (information types IT-1..3 from the facts sheet): IT-1 configuration & policy
data (`AST-CRD-POL`/`AST-CRD-EXC`, Rego), IT-2 admission decision audit records, IT-3 operational
metrics; plus the **admission-control integrity** itself (the system's reason to exist) and the
**inter-service bearer credential** (`POLICY_MANAGER_INTERNAL_TOKEN`).

**Trust anchors / assumptions.** The kube-apiserver and the CSP platform (`ZONE-EXT`) are
trusted to the extent the platform enforces them; etcd-at-rest and physical controls are
**Inherited** from the CSP. KP does **not** today authenticate the apiserver to the webhook
(POAM-005) and does **not** authenticate users to the management planes (POAM-002), so several
"trust assumptions" are in fact **unverified** and are modeled as threats below.

---

## 3. AST-WH — admission-webhook (`:8443` `/validate`,`/mutate`; `:9090` metrics)

`AST-WH` is the **enforcement plane**. The kube-apiserver calls it over `ICX-01`; it evaluates
the object against compiled Rego via embedded `AST-OPA` and returns allow/deny (+ mutations); it
publishes decision records to `AST-PM` over `ICX-02`; Prometheus scrapes `:9090` over `ICX-03`.

### 3.1 STRIDE — `ICX-01` (kube-apiserver → `AST-WH:8443`)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| WH-01 | **S** Spoofing | Any in-cluster pod (TA-1) connects to `:8443` and submits crafted `AdmissionReview`s impersonating the apiserver; webhook sets **no `tls.ClientAuth`** (no `RequireAndVerifyClientCert`), so the caller is never authenticated. | **Target:** `RequireAndVerifyClientCert` with the apiserver CA on the `:8443` listener (apiserver mTLS). **Compensating (target):** default-deny NetworkPolicy allowing only apiserver→`:8443`. | IA-3, SC-7 | **POAM-005** (P3); **POAM-007** (P4) |
| WH-02 | **T** Tampering | Path adversary (TA-4) alters the `AdmissionReview` request or the allow/deny response in transit. | **Bright spot:** `ICX-01` is pinned to **TLS 1.3** (server-auth) — the only transport-encrypted flow today; integrity protected against passive/path tampering. mTLS (P3) closes the residual endpoint-auth gap. | SC-8, SC-8(1), SC-13 | POAM-004 (P4, mgmt-plane TLS); residual endpoint-auth POAM-005 (P3) |
| WH-03 | **R** Repudiation | The apiserver identity behind an admission call cannot be proven; audit records lack source IP/UA/apiserver identity, so a forged call (see WH-01) is indistinguishable from a legitimate one. | **Bright spot (partial):** webhook logs every allow/deny decision (AU-2). **Target:** add source/identity attribution to the audit record and bind to authenticated apiserver identity. | AU-3, AU-3(1), AU-12 | **POAM-013** (P7); endpoint identity **POAM-005** (P3) |
| WH-04 | **I** Information disclosure | Object specs (Moderate IT-1) traverse `ICX-01`. | **Bright spot:** TLS 1.3 confidentiality on `:8443`. Residual: no validated FIPS module backs the TLS. | SC-8, SC-13 | **POAM-001** (P2, FIPS module) |
| WH-05 | **D** Denial of service | Flood of `AdmissionReview`s or slow-loris on `:8443`; with `failurePolicy=Fail` (fail-closed) a webhook outage becomes a **cluster-wide admission outage**. No rate limiting, body-size caps, or connection/concurrency limits exist. | **Bright spot (double-edged):** fail-closed default preserves enforcement integrity but raises availability risk. **Target:** rate limiting, request-body caps, concurrency limits; PDB/anti-affinity/HA for `AST-WH`. | SC-5, CP-10, SC-6 | **POAM-027** (P4/P8); **POAM-017** (P8) |
| WH-06 | **E** Elevation of privilege | A forged admission caller (WH-01) drives allow/deny decisions, effectively **gaining policy-enforcement authority** it should not have. | **Target:** apiserver mTLS (WH-01) removes the unauthenticated caller; least-privilege per-component SA limits blast radius. | IA-3, AC-6 | **POAM-005** (P3); **POAM-006** (P3) |
| WH-07 | **E/T** Enforcement bypass (`spec.template.spec` blindness) | **See §6 (detailed analysis + attack tree).** No shipped rule traverses `spec.template.spec`, so workload controllers (Deployment/DaemonSet/StatefulSet/ReplicaSet/Job/CronJob) and init/ephemeral containers are **never evaluated** — a silent enforcement bypass, not merely a missing policy. An attacker wraps a privileged Pod in a Deployment and is admitted. | **Target:** add `spec.template.spec` traversal + init/ephemeral container inspection; rebuild PSS Baseline/Restricted + CIS 5.x on top; admission-time Rego compile/validation. | CM-6, CM-7, SI-10 | **POAM-008** (P10); **POAM-009** (P10) |

### 3.2 STRIDE — `ICX-02` originating (`AST-WH` → `AST-PM:8080` decision publish)

> `ICX-02` is analyzed in full from the receiver side in §4.2; here it is the **plaintext
> decision-publish token** threat at the sender.

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| WH-08 | **I/S** Plaintext decision-publish token | `AST-WH`'s `DecisionPublisher` POSTs decision records **plus the static bearer `POLICY_MANAGER_INTERNAL_TOKEN`** to `http://AST-PM:8080/api/v1/decisions/internal` with **no TLS and no server-cert verification**; TA-4 can sniff the token off the wire and then impersonate the webhook (spoofing `ICX-02`). | **Target:** TLS 1.3 + audience-bound, short-TTL projected ServiceAccount token replacing the shared static secret; constant-time comparison at the receiver. | SC-8, IA-5 | **POAM-004** (P4); **POAM-020** (P3) |

### 3.3 STRIDE — `ICX-03` (Prometheus → `AST-WH:9090` metrics)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| WH-09 | **I** Information disclosure | `:9090` serves Prometheus metrics over **unauthenticated HTTP**; any in-cluster pod (TA-1) reads operational signal (decision rates, buffer state) revealing posture. | **Target:** TLS + authn on metrics endpoints; default-deny NetworkPolicy scoping Prometheus→`:9090`. | SC-8, AC-3, SC-7 | **POAM-004** (P3); **POAM-002** (P3); **POAM-007** (P4) |
| WH-10 | **D** Denial of service | Unauthenticated `:9090` scrape endpoint can be hammered with no rate/connection limits. | **Target:** rate/connection limits; NetworkPolicy scoping. | SC-5, SC-7 | **POAM-027** (P4); **POAM-007** (P4) |

---

## 4. AST-PM — policy-manager REST API + CRD reconcile (`:8080`; `:9091` metrics)

`AST-PM` is the **control plane**: REST API `/api/v1` on `:8080`, decision sink (`ICX-02`),
dashboard feed source (`ICX-04`), and CRD reconcile + Lease against the kube-apiserver
(`ICX-06`). Metrics on `:9091` (`ICX-03`).

### 4.1 STRIDE — `ICX` exposure of the REST API `:8080` (unauthenticated API)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| PM-01 | **S** Spoofing / unauthenticated API | `internal/policymanager/router.go` has **no auth middleware**; any reachable caller (TA-1/TA-2) is implicitly trusted on `/api/v1`. No principal exists to spoof because none is required. | **Target:** OIDC/end-user authentication on every `/api/v1` route; remove anonymous access. **Compensating (target):** NetworkPolicy scoping callers to `AST-WH`/`AST-DB`. | IA-2, IA-2(8), AC-14 | **POAM-002** (P3); **POAM-007** (P4) |
| PM-02 | **I** Information disclosure | Unauthenticated `GET /api/v1` exposes **all policy data** (IT-1) and the decision feed (IT-2) to any reachable caller. | **Target:** authN + role-based authZ (viewer/editor/admin); TLS 1.3 on `:8080`. | AC-3, IA-2, SC-8 | **POAM-003** (P3); **POAM-002** (P3); **POAM-004** (P4) |
| PM-03 | **E** Elevation of privilege / no authZ model | There is **no application-layer authorization** (no viewer/editor/admin; a single global `ALLOW_WRITES` boolean is the only gate). Any caller that can write can perform any write; **no separation of duties** between read and write. | **Target:** RBAC role model enforced on every API/dashboard action; SoD between read and write. | AC-3, AC-5, AC-6 | **POAM-003** (P3) |
| PM-04 | **T** Tampering / input validation | API request bodies and Rego in CRDs are weakly validated; a malformed or **always-allow** Rego rule can be installed with no admission-time compile check, schema, or per-rule test. | **Bright spot (partial):** config validation enforces TLS1.3/failure-mode (SI-10). **Target:** admission-time Rego compile/validation + schema + per-rule test harness; API request validation. | SI-10, CM-6 | **POAM-009** (P10) |
| PM-05 | **R** Repudiation | Management-plane actions (CRD CRUD, exception approvals, `ALLOW_WRITES` toggles) have **zero production audit callers** and no authenticated principal, so config changes are not in the audit trail and actions attribute to `system:unauthenticated`. | **Target:** wire management-plane audit events to real authenticated principals (depends on P3 authN); system-wide correlated trail. | AU-2, AU-3, AU-12, AU-12(1) | **POAM-013** (P7); **POAM-028** (P7) |
| PM-06 | **D** Denial of service | `:8080` has no rate limiting, body-size caps, or concurrency limits; resource exhaustion can starve the control plane and stall reconcile. | **Target:** rate limiting + body caps + concurrency limits + ResourceQuota/LimitRange. | SC-5 | **POAM-027** (P4/P8) |

### 4.2 STRIDE — `ICX-02` terminating (`AST-WH` → `AST-PM:8080/api/v1/decisions/internal`)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| PM-07 | **S** Spoofing | `ICX-02` authenticates the publisher only with the **shared static bearer token**; any holder (sniffed per WH-08, or any pod with the Secret) can spoof `AST-WH` and **inject forged decision records** (IT-2 integrity). The bearer check uses **non-constant-time comparison** (timing oracle). | **Target:** audience-bound short-TTL projected SA tokens with per-caller identity; `crypto/subtle` constant-time comparison; TLS. | IA-5, IA-3, SC-8 | **POAM-020** (P3); **POAM-004** (P4) |
| PM-08 | **I** Information disclosure | Decision records (IT-2) + the bearer token transit `ICX-02` in **cleartext HTTP** (see WH-08). | **Target:** in-cluster TLS/mTLS for `ICX-02`. | SC-8, SC-8(1) | **POAM-004** (P4) |
| PM-09 | **T** Tampering | Path adversary (TA-4) alters decision records in flight on cleartext `ICX-02`, corrupting the audit/decision feed. | **Target:** TLS integrity + tamper-evident (HMAC/hash-chain) audit records downstream. | SC-8, AU-9, AU-9(3) | **POAM-004** (P4); **POAM-010** (P7) |

### 4.3 STRIDE — `ICX-04` terminating (`AST-DB` → `AST-PM:8080`)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| PM-10 | **I/S** | Dashboard feed pull rides **cleartext HTTP** and the same unauthenticated `/api/v1` surface (PM-01/PM-02); a path adversary or rogue caller can read or impersonate the feed. | **Target:** TLS on `ICX-04`; authN/authZ on `/api/v1`. | SC-8, IA-2, AC-3 | **POAM-004** (P4); **POAM-002** (P3) |

### 4.4 STRIDE — `ICX-06` (`AST-PM` ↔ kube-apiserver: CRD reconcile + Lease)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| PM-11 | **E** Elevation of privilege / over-broad SA | `AST-WH` and `AST-PM` **share one ServiceAccount/ClusterRole** granting **cluster-wide get/list/watch on Secrets in all namespaces** and **full CRUD on validating/mutating webhook configurations**. A compromise of either pod yields cluster-wide secret read and the ability to rewrite/delete the webhook configuration (disabling enforcement). | **Target:** split into per-component SAs; scope ClusterRoles to `Policy`/`PolicyException` + Lease + status only; remove cluster-wide secret read and webhook-config CRUD. | AC-6, AC-6(1), AC-5 | **POAM-006** (P3) |
| PM-12 | **T** Tampering (CRD data) | TA-3 edits `AST-CRD-POL`/`AST-CRD-EXC` to weaken or disable policy; an always-allow Rego string is accepted unvalidated (PM-04). | **Target:** admission-time Rego validation/schema; least-privilege RBAC on CRD write; management-plane audit. | SI-10, CM-6, AU-12 | **POAM-009** (P10); **POAM-006** (P3) |
| PM-13 | **S/I** Spoofing/disclosure on `ICX-06` | `ICX-06` rides in-cluster TLS + SA token to the apiserver. Residual: the SA token is over-privileged (PM-11) and the bearer Secret is unencrypted at rest. | **Bright spot (partial):** in-cluster TLS to apiserver; leader-election Lease provides single-writer integrity. **Target:** least-priv SA; secret encryption at rest (KMS/EncryptionConfiguration). | SC-8, AC-6, SC-28 | **POAM-006** (P3); **POAM-021** (P2) |
| PM-14 | **D** Denial of service / availability | Single-replica, leader-election-gated `AST-PM` with no PDB and empty affinity; a reconcile-loop failure or eviction stalls policy updates and (with fail-closed `AST-WH`) risks enforcement staleness. | **Bright spot (partial):** leader election + replicas aid recovery. **Target:** HA `AST-PM`, PDB, anti-affinity/topology spread, DR runbook. | CP-10, SC-6 | **POAM-017** (P8) |

### 4.5 STRIDE — `ICX-03` (Prometheus → `AST-PM:9091` metrics)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| PM-15 | **I/D** | `:9091` metrics over unauthenticated HTTP (same as WH-09/WH-10); leaks control-plane signal and is DoS-reachable by any pod. | **Target:** TLS+authn on metrics; NetworkPolicy scoping Prometheus→`:9091`; rate limits. | SC-8, AC-3, SC-7, SC-5 | **POAM-004** (P3); **POAM-002** (P3); **POAM-007** (P4); **POAM-027** (P4) |

---

## 5. AST-DB — dashboard BFF write-gating (`ALLOW_WRITES`) (`:8090`; `:9092` metrics)

`AST-DB` is the **presentation plane**: serves `AST-SPA` + BFF `/api` + reverse-proxy
`/api/v1`→`AST-PM:8080` on `:8090`. Operators reach it over `ICX-05`; it pulls from `AST-PM`
over `ICX-04` (originating). Metrics on `:9092` (`ICX-03`). It is **read-only unless
`ALLOW_WRITES=true`** — the central design control of this component.

### 5.1 STRIDE — `ICX-05` (operators/users → `AST-DB:8090`)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| DB-01 | **S** Spoofing / unauthenticated dashboard | The BFF has **no login/OIDC/session**; any reachable user (TA-2) is anonymous-equivalent. There is no identity to spoof because none is required. | **Target:** OIDC login + session on the BFF; remove anonymous access. **Compensating (target):** NetworkPolicy + ingress scoping. | IA-2, AC-14, AC-17 | **POAM-002** (P3); **POAM-007** (P4) |
| DB-02 | **E** Elevation of privilege / write-gating bypass | **See §6.2.** `ALLOW_WRITES` is a single **global boolean** with **no per-user role**. If an operator enables writes (a legitimate operational need), **every** anonymous caller on `:8090` gains write authority to policy via the proxy — there is no SoD and no per-action authZ. Conversely, while `ALLOW_WRITES=false` the read-only default is a genuine integrity safeguard. | **Bright spot:** read-only by default (`ALLOW_WRITES=false`) limits integrity exposure in the default posture. **Target:** replace the global boolean with authenticated RBAC (viewer/editor/admin) so enabling writes does not grant universal write. | AC-3, AC-5, AC-6, IA-2 | **POAM-003** (P3); **POAM-002** (P3) |
| DB-03 | **I** Information disclosure | `ICX-05` is **cleartext HTTP**; dashboard content and proxied policy/decision data (IT-1/IT-2, Moderate) are exposed to TA-4 and to any unauthenticated viewer (DB-01). | **Target:** TLS + OIDC; HSTS/secure cookies once authN lands. | SC-8, AC-17(2), AC-12 | **POAM-004** (P4); **POAM-002** (P3); **POAM-036** (P3) |
| DB-04 | **R** Repudiation | Dashboard write actions (when `ALLOW_WRITES=true`) attribute to no authenticated principal, so policy changes via the dashboard are unattributable. | **Target:** authenticated principals + management-plane audit (depends on P3 authN). | AU-2, AU-3, AU-12 | **POAM-013** (P7); **POAM-002** (P3) |
| DB-05 | **D** Denial of service | `:8090` has no rate limiting, body caps, or session/idle limits; an anonymous flood can exhaust the BFF and its proxy connections to `AST-PM`. | **Target:** rate limiting + body caps + connection limits + session/idle timeout. | SC-5, AC-12 | **POAM-027** (P4); **POAM-036** (P3) |

### 5.2 STRIDE — `ICX-04` originating (`AST-DB` → `AST-PM:8080`)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| DB-06 | **I/T** | The proxy forwards over **cleartext HTTP** to the **unauthenticated** `AST-PM` API; a path adversary (TA-4) can read or alter proxied requests/responses, and the proxy itself carries no caller identity to `AST-PM`. | **Target:** TLS on `ICX-04`; end-to-end authN so the proxy presents the user identity to `AST-PM`. | SC-8, IA-2, AC-3 | **POAM-004** (P4); **POAM-002** (P3) |

### 5.3 STRIDE — `ICX-03` (Prometheus → `AST-DB:9092` metrics)

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| DB-07 | **I/D** | `:9092` metrics over unauthenticated HTTP (same class as WH-09/PM-15). | **Target:** TLS+authn; NetworkPolicy scoping; rate limits. | SC-8, AC-3, SC-7, SC-5 | **POAM-004** (P3); **POAM-002** (P3); **POAM-007** (P4); **POAM-027** (P4) |

---

## 6. Focused analyses (required deep dives)

### 6.1 Admission bypass — including `spec.template.spec` enforcement blindness

The webhook is the system's only enforcement point, so **any** way to (a) reach admission as a
non-apiserver caller, (b) disable/rewrite the webhook configuration, or (c) submit an object the
ruleset does not actually inspect, is an enforcement bypass. Two structurally different bypasses
exist today:

1. **Caller bypass (unauthenticated `:8443`).** No client-cert auth (WH-01, POAM-005); any pod
   can drive admission decisions. Compounded by the over-broad shared SA (PM-11, POAM-006),
   which can **CRUD the webhook configuration** to point it elsewhere or delete it outright,
   disabling enforcement cluster-wide.
2. **Coverage bypass (`spec.template.spec` enforcement blindness).** No shipped Rego rule
   traverses `spec.template.spec` (WH-07, POAM-008). Workload controllers create Pods *indirectly*
   via their pod template; because the rules inspect only the top-level object (e.g., a bare Pod),
   a **privileged Pod wrapped in a Deployment/DaemonSet/StatefulSet/ReplicaSet/Job/CronJob is
   admitted unchecked**, and `initContainers`/`ephemeralContainers` are never inspected. This is a
   *silent* bypass: the system returns "allow" and appears healthy. POAM-009 (unvalidated/always-
   allow Rego) widens the same gap from the policy-authoring side.

**Attack tree — "Attacker runs a privileged workload despite KP" (text form).**

```
GOAL: Run a privileged / policy-violating workload in a KP-protected cluster
└─ OR
   ├─ A. Bypass the admission caller check
   │     └─ AND
   │        ├─ A1. Reach AST-WH:8443 from an in-cluster pod      [TA-1; enabled by POAM-007 no NetworkPolicy]
   │        └─ A2. Webhook accepts non-apiserver client          [POAM-005 no RequireAndVerifyClientCert → IA-3]
   │              (no mTLS) → attacker scripts allow decisions
   │
   ├─ B. Disable / rewrite enforcement
   │     └─ OR
   │        ├─ B1. Compromise a pod sharing the over-broad SA     [POAM-006 → AC-6]
   │        │      └─ CRUD validating/mutatingwebhookconfiguration → delete/redirect webhook
   │        └─ B2. Read cluster-wide Secrets via same SA          [POAM-006 → AC-6]
   │               └─ steal POLICY_MANAGER_INTERNAL_TOKEN / TLS keys [POAM-020/POAM-021]
   │
   ├─ C. Evade policy coverage (no auth needed — works on a compliant cluster)   ← lowest-cost path
   │     └─ OR
   │        ├─ C1. Wrap privileged Pod in a Deployment/DaemonSet/StatefulSet/    [POAM-008 → CM-6]
   │        │      ReplicaSet/Job/CronJob → spec.template.spec never traversed
   │        ├─ C2. Hide payload in initContainers / ephemeralContainers          [POAM-008 → CM-6]
   │        └─ C3. Install an always-allow / broken Rego rule (no compile check)  [POAM-009 → SI-10]
   │
   └─ D. Take the webhook down to force fail-open (only if misconfigured)
         └─ AND
            ├─ D1. DoS AST-WH:8443 (no rate/concurrency limits)                   [POAM-027 → SC-5]
            └─ D2. failure_mode set to fail-open by operator                      [mitigated by fail-closed default]
                   (DEFAULT IS fail-closed — this branch fails on a default install)
```

**Reading the tree.** Branch **C** is the cheapest and needs **no authentication and no
privilege** — it works even against an otherwise well-configured cluster — which is why
POAM-008 is rated a Critical *enforcement* gap rather than a missing-feature nicety. Branch **D**
is blocked on a default install by the **fail-closed** bright spot. Branches **A/B** require
in-cluster reach (POAM-007) and are closed by apiserver mTLS (POAM-005) and the least-privilege
SA split (POAM-006).

**Threat → mitigation → control → POA&M summary for admission bypass.**

| Bypass path | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|
| A — unauthenticated `:8443` caller | apiserver mTLS (`RequireAndVerifyClientCert`) | IA-3 | **POAM-005** (P3) |
| A1/B — in-cluster reachability | default-deny NetworkPolicy + scoped allow | SC-7, SC-7(5) | **POAM-007** (P4) |
| B — webhook-config CRUD / cluster Secret read | per-component least-privilege SA split | AC-6 | **POAM-006** (P3) |
| C1/C2 — `spec.template.spec` / init/ephemeral blindness | template traversal + init/ephemeral inspection + PSS rebuild | CM-6, CM-7 | **POAM-008** (P10) |
| C3 — always-allow / broken Rego | admission-time Rego compile/validation + schema + tests | SI-10 | **POAM-009** (P10) |
| D — forced fail-open | fail-closed default (**implemented**); rate/concurrency limits | SC-5, CP-10 | mitigated (default); **POAM-027** (P4) |

### 6.2 PolicyException abuse

`AST-CRD-EXC` (`PolicyException`) lets operators carve out exemptions from policy enforcement.
Because there is **no application-layer authZ** (POAM-003), **no admission-time validation of the
exception's scope/expiry** beyond what the engine consumes, and **no management-plane audit of who
created/approved an exception** (POAM-013), the exception mechanism is a high-value abuse target.

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| EXC-01 | **E** Elevation / over-broad exception | TA-3 (or any caller, since writes are gated only by `ALLOW_WRITES`/RBAC-less API) creates a `PolicyException` with an over-broad selector (e.g., namespace- or cluster-wide, no expiry) that **silently neuters enforcement** for a large surface. | **Target:** RBAC so only an authorized approver role can create/approve exceptions; SoD between requester and approver; scope/expiry validation at admission. | AC-3, AC-5, AC-6, SI-10 | **POAM-003** (P3); **POAM-009** (P10) |
| EXC-02 | **R** Repudiation | Exception creation/approval has **no authenticated principal and no audit record**, so an abusive exemption cannot be attributed or reconstructed. | **Target:** management-plane audit of exception CRUD tied to authenticated principals; correlated trail linking exception → downstream admitted objects. | AU-2, AU-3, AU-12, AU-12(1) | **POAM-013** (P7); **POAM-028** (P7) |
| EXC-03 | **T** Tampering / persistence | An exception with no expiry persists indefinitely (no TTL enforcement in code), becoming a permanent enforcement hole that outlives its justification. | **Target:** mandatory expiry + periodic review of active exceptions; validation gate. | SI-10, CM-6, AC-6(7) | **POAM-009** (P10); review procedural (P12) |
| EXC-04 | **I** Disclosure (recon) | Unauthenticated read of `/api/v1` (PM-02) reveals existing exceptions, letting an attacker discover the cheapest enforcement gap to exploit. | **Target:** authN/authZ on the API; least-disclosure on exception listing. | AC-3, IA-2 | **POAM-002** (P3); **POAM-003** (P3) |

### 6.3 Unauthenticated API / dashboard (consolidated)

The management/presentation planes (`AST-PM:8080`, `AST-DB:8090`) and all metrics planes are
**unauthenticated** (POAM-002) with **no authZ model** (POAM-003) and **cleartext HTTP**
(POAM-004), and — absent a NetworkPolicy (POAM-007) — reachable by any in-cluster pod. There is
**no compensating boundary control** today, so the missing authN is not offset. The bright spots
that *partially* contain this are the dashboard **read-only default** (`ALLOW_WRITES=false`) and
**pod hardening**; neither restores confidentiality or authentication. Mitigation is the P3
identity work (OIDC + RBAC), the P4 network segmentation (default-deny + scoped flows), and the
P3/P4 TLS work; session protections (HSTS, idle timeout, secure cookies) follow in P3 (POAM-036).

### 6.4 Plaintext decision-publish token (consolidated)

`ICX-02` posts decision records **and** the static shared bearer token over cleartext HTTP with
no server-cert verification (WH-08/PM-07/PM-08). The token is the **only** inter-service
authenticator, is mounted as a plain Opaque Secret with **no rotation** and **no per-caller
identity**, and is compared **non-constant-time** (timing oracle). A path adversary or any pod
with the Secret can replay it to forge decision records or otherwise act as `AST-WH`. Mitigation:
TLS/mTLS on `ICX-02` (POAM-004, P4), replacement with audience-bound short-TTL projected SA tokens
+ rotation + `crypto/subtle` comparison (POAM-020, P3), and secret encryption at rest (POAM-021,
P2).

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| TOK-01 | **I** Token sniffed in transit | cleartext `ICX-02` | TLS/mTLS on `ICX-02` | SC-8 | **POAM-004** (P4) |
| TOK-02 | **S** Token replay → impersonate `AST-WH` | static, no per-caller identity, no rotation | audience-bound short-TTL projected SA token; rotation | IA-5, IA-3 | **POAM-020** (P3) |
| TOK-03 | **I** Timing oracle on bearer check | non-constant-time comparison | `crypto/subtle` constant-time compare | IA-5, SI-10 | **POAM-020** (P3) |
| TOK-04 | **I** Token/key at rest in plain Secret | no EncryptionConfiguration/KMS | secret encryption at rest (KMS/EncryptionConfiguration) | SC-28, SC-28(1) | **POAM-021** (P2) |

### 6.5 Supply-chain entry points

KP is delivered as container images + a Helm chart; the build/release pipeline is a primary
attack surface (TA-5). The facts sheet flags untrustworthy CI, unpinned images/actions, and
signing "theater" as foundational gaps.

| # | STRIDE | Threat | Mitigation | Control ID | POA&M (phase) |
|---|---|---|---|---|---|
| SUP-01 | **T** Untrustworthy CI (toolchain skew) | CI pins Go 1.20/1.21 while `go.mod` requires 1.25.0, so the gating pipeline **cannot build the shipped code** — every green result is untrustworthy and a malicious change could pass undetected. | **Target:** align CI Go toolchain to `go.mod`, remove broken steps, make CI build/test the real artifacts. | SA-11, SA-15, CM-5 | **POAM-014** (P1); **POAM-034** (P11) |
| SUP-02 | **T/S** Signing theater / no provenance | No OIDC `id-token: write`, so keyless cosign signing and SBOM attestation cannot succeed; no SLSA provenance; SBOMs not attested to digests. Consumers cannot verify authenticity. | **Target:** enable `id-token: write` + keyless cosign; generate/publish SLSA provenance; attest SBOMs to digests. | SR-4, SR-3, SR-11 | **POAM-015** (P6) |
| SUP-03 | **T** Mutable references | GitHub Actions pinned to `@master`/mutable tags and base/workload images use floating tags with `pullPolicy: IfNotPresent` and no `@sha256` digests — a moved tag swaps code under the build/deploy. | **Target:** pin all actions and base/workload images by immutable digest; digest-based deploy option; configuration baseline + image inventory. | CM-2, SR-3, SR-5 | **POAM-023** (P5/P6); **POAM-033** (P6) |
| SUP-04 | **T** Unsigned image admission | The webhook ships no image-signature/provenance admission rule, so the cluster (and KP's own images) can run unsigned/unverified images. | **Target:** admission policy verifying cosign signatures/provenance; consumer verify docs. | CM-14, SI-7, SI-7(1) | **POAM-035** (P6/P10) |
| SUP-05 | **I/T** Non-gating vulnerability scanning | Trivy runs SARIF-only with no severity threshold/exit-code; no govulncheck/CodeQL/secret-scanning/SCA, no dependency-update automation — CRITICAL/HIGH CVEs ship silently. | **Target:** gate Trivy on CRITICAL/HIGH; add govulncheck/CodeQL/secret-scan/SCA; Dependabot/Renovate; SLA-bound vuln program feeding the POA&M. | RA-5, SI-2, SA-11(1) | **POAM-025** (P11); **POAM-026** (P11) |
| SUP-06 | **R** Supply-chain governance | No SECURITY.md/coordinated-disclosure policy and no SCRM plan tying artifacts to controls for the ATO package. | **Target:** author SECURITY.md + disclosure SLAs and an SCRM plan; this threat model is one of the required artifacts. | SR-3, SR-2 | **POAM-033** (P6) |

---

## 7. Residual-risk summary and POA&M reconciliation

The dominant residual risks are: **(1) admission bypass** via unauthenticated `:8443`
(POAM-005), webhook-config CRUD on the over-broad SA (POAM-006), and the `spec.template.spec`
coverage gap (POAM-008/POAM-009); **(2) unauthenticated, cleartext, unsegmented management/metrics
planes** (POAM-002/POAM-003/POAM-004/POAM-007); **(3) the plaintext shared inter-service token**
(POAM-020/POAM-004/POAM-021); **(4) PolicyException abuse** lacking authZ and audit
(POAM-003/POAM-013); and **(5) supply-chain integrity** (POAM-014/POAM-015/POAM-023/POAM-025/
POAM-033/POAM-035). Each is an **Open** [POA&M](poam.csv) item with a scheduled remediation phase.

The bright spots that genuinely reduce risk today — **TLS 1.3 on `AST-WH:8443`**, the
**fail-closed admission default**, the dashboard **read-only-by-default** (`ALLOW_WRITES=false`),
**pod hardening**, and **leader election** — are noted inline; none of them, individually or
together, closes the bypass, authentication, or supply-chain risks above.

Every threat in §§3–6 maps to a control in the [control matrix](control-matrix.csv) and, where
open, to a [POA&M](poam.csv) id and a P1–P12 phase. As those phases land, the "current posture"
and POA&M columns here are revised so the threat model, control matrix, and POA&M stay
reconciled. This document is the canonical realization of the **Threat Modeling** process in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## 8. References

- [System Facts Sheet](system-facts.md) — canonical asset IDs, ports, trust zones, `ICX-01..06`.
- [Data Flow Diagram](diagrams/data-flow.md) — trust-boundary crossings analyzed here.
- [Authorization Boundary Diagram](diagrams/authorization-boundary.md).
- [Interconnection Register](interconnections.md) (`ICX-01..06`).
- [Security Architecture (PL-8)](security-architecture.md).
- [Control Matrix](control-matrix.csv) · [POA&M](poam.csv) · [Inventory](inventory.csv).
- [SSP](ssp/SSP.md) (§7.16 RA, §7.17 SA) · [CRM](CRM.md) (RA — Risk Assessment) · [SAP](assessment/SAP.md).
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) — Threat Modeling process this document realizes.
- NIST SP 800-53 Rev 5 (RA-3, SA-11, SA-15, IA-2/IA-3, AC-3/AC-5/AC-6, AU-3/AU-12, SC-5/SC-7/SC-8/SC-13/SC-28, CM-6/CM-14, SI-7/SI-10, SR-3/SR-4); FedRAMP Moderate baseline; FIPS-199; STRIDE (Microsoft SDL).
