---
title: "Penetration Test Plan — Kube-Policies (KP)"
control_family: "CA — Assessment, Authorization, and Monitoring"
controls: "CA-8, CA-8(1), SA-11, RA-5(5), SC-8"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# Penetration Test Plan — Kube-Policies (KP)

FIPS-199 categorization: **Moderate**. Standard: **NIST SP 800-53 Rev 5**, **FedRAMP
Moderate** baseline. This plan satisfies **CA-8** (Penetration Testing) and the
**CA-8(1)** enhancement (Independent Penetration Agent or Team), and complements the
developer-security-testing controls **SA-11** and **RA-5(5)** that are already
implemented in CI.

This Penetration Test Plan is a **Draft scaffold** for a Proof-of-Concept being driven to
assessment readiness. It defines **how** a penetration test of Kube-Policies (KP) will be
scoped, conducted, and reported; **it does not record results, and no penetration test
has been performed.** Execution is a separate human/3PAO activity scheduled as work unit
**P12-WU-04** (internal pre-assessment review) and the external CA-8(1) engagement that
follows. Findings from any executed test are routed to the
[POA&M](../compliance/POAM.md); the assessment-wide methodology and rules of engagement
are defined in the [Security Assessment Plan (SAP)](../compliance/assessment/SAP.md),
which this plan **complements** rather than replaces.

> **Honesty note.** KP is an as-built PoC with known foundational gaps (no FIPS-validated
> cryptographic module, unauthenticated control/metrics planes, no enforced NetworkPolicy
> without a supporting CNI, `spec.template.spec` enforcement history, audit durability
> dependent on opt-in persistence). The pen test is **expected to generate findings**.
> This plan scopes the test against the system as it is; it makes no claim that the system
> is hardened against the scenarios it enumerates. Named roles are **not yet staffed**;
> role titles are used with the qualifier "TBD — assign". Do not infer individuals.

> **Relationship to automated DAST.** The repository already runs automated OWASP ZAP
> baseline scans and TLS/cipher checks (`scripts/test/dast.sh`,
> [`.github/workflows/dast.yml`](../../.github/workflows/dast.yml); described in
> [secure-sdlc.md](secure-sdlc.md) § 5.2). That automation is **complementary continuous
> scanning** — a baseline, low-false-positive web scan on a scheduled/scoped trigger. It is
> **explicitly not a substitute** for the manual, adversarial, Kubernetes-aware penetration
> test this plan describes, and CA-8 is not satisfied by DAST alone.

**Annual review.** This plan is reviewed at least **annually** (last review
**2026-06-02**; next review **2027-06-02**) and re-baselined upon any significant change to
the system, the authorization boundary, or the applicable baseline (see § 4).

---

## 1. Purpose and scope

The purpose of this plan is to establish the scope, methodology, rules of engagement,
cadence, and finding-handling for an **adversarial penetration test** of KP sufficient to
support the CA-8 / CA-8(1) control requirement under the FedRAMP Moderate baseline.

Canonical component names, ports, trust zones, and interconnection IDs are taken verbatim
from the [System Facts Sheet](../compliance/system-facts.md); the assessed boundary is the
[Authorization Boundary Diagram](../compliance/diagrams/authorization-boundary.md). This
plan does not redefine those facts — it targets them.

### 1.1 In-scope targets (`ZONE-SYS`, In-Boundary)

| Target | Asset | Assessed attack surface |
|---|---|---|
| Admission webhook TLS endpoint | `AST-WH` | `8443/tcp` TLS 1.3 (`/validate`, `/mutate`); transport, cipher posture, AdmissionReview handling (`ICX-01`) |
| Policy-manager REST API | `AST-PM` | `8080/tcp` HTTP `/api/v1/*`; authn/authz, input handling, decisions endpoint (`ICX-02`, `ICX-04`) |
| Dashboard BFF | `AST-DB` | `8090/tcp` HTTP (SPA + `/api` + reverse-proxy → `AST-PM:8080`); write-gating (`ALLOW_WRITES`), session handling (`ICX-05`) |
| CRDs | `AST-CRD-POL`, `AST-CRD-EXC` | `Policy` / `PolicyException` schema, validation, RBAC, reconcile behavior |
| RBAC / ServiceAccount boundaries | `AST-CHART` | ClusterRole/Role scope, SA-token automount, privilege boundaries |
| OPA / Rego policy engine | `AST-OPA` | Embedded evaluator in `AST-WH` and `AST-PM`; evaluation correctness, resource exhaustion, malformed input |
| Metrics planes | `AST-WH`/`AST-PM`/`AST-DB` | `:9090`/`:9091`/`:9092` HTTP metrics exposure (`ICX-03`) |

### 1.2 Out of scope (assessed only for responsibility-assertion correctness)

- The **kube-apiserver** and **etcd** internals, and any **CSP-inherited infrastructure**
  (the hosting CSP control plane, host network underpinning SC-7, PE/MA families). These are
  `ZONE-EXT` / **Inherited** per the [SAP](../compliance/assessment/SAP.md) § 2.3 and the
  [CRM](../compliance/CRM.md); the CSP authorization package is the evidence of record. The
  pen test reviews **only** the correctness of the KP-side responsibility assertion and the
  KP-controlled interface at each boundary-crossing interconnection — it does **not** actively
  test inherited assets.
- Any tenant or workload outside the KP authorization boundary; any production environment
  (see § 3).

---

## 2. Methodology

The penetration test follows the **OWASP Web Security Testing Guide (WSTG)** for the
HTTP/TLS surfaces and the **Penetration Testing Execution Standard (PTES)** phase model
(pre-engagement, intelligence gathering, threat modeling, vulnerability analysis,
exploitation, post-exploitation, reporting). Methodology is **gray-box**: the assessor is
given read access to the repository at the frozen baseline (§ 3) and the
[threat model](threat-model.md), and least-privilege access to the assessment environment.

Beyond generic web testing, the assessor executes the following **Kubernetes-specific
attack scenarios** drawn from KP's threat model and remediation history. Each scenario is
mapped to the weakness it probes; open weaknesses are tracked in the
[POA&M](../compliance/POAM.md).

| # | Scenario | Target(s) | What it probes |
|---|---|---|---|
| K1 | **Admission-controller bypass** | `AST-WH`, `AST-OPA` | Attempt to slip a non-conformant pod past enforcement via nested pod specs — `spec.template.spec` (Deployment/Job/CronJob), `initContainers`, and `ephemeralContainers`. The policy-engine `spec.template.spec` enforcement gap is the historical weakness behind **POAM-008 (CM-6)**; confirm the P10 traversal fix holds and probe for residual blind spots. |
| K2 | **Policy-exception abuse** | `AST-CRD-EXC`, `AST-PM`, `AST-OPA` | Create/forge a `PolicyException` to suppress enforcement beyond its intended scope (over-broad selector, wrong namespace, expired-but-honored exception); attempt to evaluate an exception against an object it should not cover. |
| K3 | **CRD manipulation / privilege via policy edits** | `AST-CRD-POL`, `AST-PM`, `ICX-06` | Edit a `Policy` CRD to weaken or disable enforcement, inject a permissive rule, or escalate effect via the reconcile path; test whether CRD write authority maps to an effective control-bypass primitive. |
| K4 | **ServiceAccount-token theft & RBAC escalation** | `AST-CHART`, RBAC, SA boundaries | Assess the over-broad shared ServiceAccount / ClusterRole weakness (**POAM-006, AC-6**): attempt token reuse, lateral movement, and privilege escalation from a compromised KP pod; verify `automountServiceAccountToken=false` and least-privilege role scoping. |
| K5 | **TLS / cipher downgrade on `:8443`** | `AST-WH`, `ICX-01` | Attempt protocol/cipher downgrade against the pinned TLS 1.3 endpoint; verify no fallback to TLS ≤1.2 or weak suites; check the unauthenticated-client weakness (**POAM-005, IA-3** — webhook accepts any client without apiserver mTLS). Maps to **SC-8** transport protection. |
| K6 | **Fail-open abuse** | `AST-WH` | If the webhook is (mis)configured to `fail-open`, induce evaluation/transport errors and attempt to drive an admit that would otherwise be denied; confirm the shipped `fail-closed` default cannot be silently flipped and that fail-open admits are observable (the `kube_policies_admission_fail_open_total` metric). |
| K7 | **DoS against the admission timeout** | `AST-WH`, `AST-OPA` | Probe the application-layer availability controls (rate-limit, body-size, concurrency, SSE caps — **POAM-027, SC-5**) and attempt to exhaust evaluation within the apiserver admission timeout window so the webhook stalls or times out (forcing fail-open/-closed at scale). Destructive/DoS testing is **RoE-gated** (§ 3). |
| K8 | **OPA / Rego evaluator fuzzing** | `AST-OPA` | Fuzz the embedded evaluator with malformed/adversarial AdmissionReview and Rego inputs, extending the existing native Go fuzz targets — `FuzzAdmissionRequest` ([`internal/admission/controller_fuzz_test.go`](../../internal/admission/controller_fuzz_test.go)) and `FuzzEngineEvaluate` ([`internal/policy/engine_fuzz_test.go`](../../internal/policy/engine_fuzz_test.go)) — looking for panics, evaluation hangs, or denial-of-evaluation. Maps to **SA-11(8)** / **SI-10**. |
| K9 | **Management/metrics-plane exposure** | `AST-PM`, `AST-DB`, metrics ports | Test the unauthenticated management & enforcement planes (**POAM-002, IA-2**; **POAM-003, AC-3**): direct REST calls bypassing the dashboard, write attempts against `ALLOW_WRITES` gating, and information disclosure via the unauthenticated `:9090/:9091/:9092` metrics endpoints (`ICX-03`). |

These scenarios extend — they do not replace — the generic WSTG coverage (authentication,
authorization, input validation, error handling, transport, configuration) applied to each
HTTP/TLS surface in § 1.1.

---

## 3. Rules of engagement (RoE)

The following RoE govern conduct of the penetration test. They are confirmed and signed
before testing begins by the assessor, the System Owner, and the Authorizing Official, and
are consistent with the assessment-wide RoE in the [SAP](../compliance/assessment/SAP.md)
§ 6.

- **Environment.** Testing is performed **only** against a dedicated, non-production
  assessment environment — a Kind or k3s cluster deployed from the frozen baseline, per the
  testing guidance in [`TESTING.md`](../../TESTING.md). No pen-test activity is performed
  against any production tenant or shared cluster.
- **Written authorization.** Active testing (exploitation, fault injection, scanning of
  live endpoints) requires **written authorization** captured in the signed RoE, scoped to
  the In-Boundary `ZONE-SYS` assets in § 1.1. `ZONE-EXT` and Inherited assets are **not**
  actively tested.
- **Destructive testing.** Denial-of-service and other destructive tests (notably scenario
  **K7**) are **prohibited unless explicitly authorized** in the RoE and scheduled in a
  maintenance window against a disposable environment.
- **Least-privilege, time-boxed access.** The assessor is granted least-privilege,
  time-boxed credentials to the assessment environment and read access to the repository at
  the frozen baseline. Access is revoked at the end of the engagement window.
- **Data handling.** Only synthetic/test data is used. Any decision/audit records (IT-2) or
  CRD data (IT-1) collected as evidence are treated as **Moderate** and stored in the
  assessment evidence repository with access restricted to the assessment team. See the
  information-type definitions in the [System Facts Sheet](../compliance/system-facts.md).
- **Evidence integrity.** All test activity and tooling output is captured with the
  **frozen commit hash, tool name and version, and UTC timestamps** to ensure
  reproducibility. The frozen baseline (commit/tag) is recorded at engagement kickoff.
- **Communications and escalation.** A named point of contact (System Owner, TBD — assign)
  is available during test windows. Any safety-affecting or out-of-scope condition halts
  testing immediately and is escalated.

---

## 4. Cadence

A penetration test is conducted:

- **At least annually**, aligned with the annual control-assessment cadence in the
  [SAP](../compliance/assessment/SAP.md) and the next-review date of this plan
  (**2027-06-02**); **and**
- **On every major or significant change** to the system — a new component or listening
  port, a change to the authorization boundary or an interconnection (`ICX-01..06`), a
  change to the policy-engine traversal logic, the RBAC/ServiceAccount model, or the TLS
  configuration. A significant change triggers a **delta penetration test** scoped to the
  changed surface, tied to the significant-change process referenced in the
  [SAP](../compliance/assessment/SAP.md) § 5.

Between full engagements, the automated DAST baseline ([`.github/workflows/dast.yml`](../../.github/workflows/dast.yml))
and nightly fuzz provide continuous, complementary coverage (§ secure-sdlc.md 5.1–5.2) but
do not reset the annual pen-test clock.

---

## 5. Findings → remediation → retest

Findings are handled as a closed loop and are **not** allowed to remain untracked:

1. **Severity rating.** Each finding is rated `Critical | High | Moderate | Low` using
   CVSS v3.1 adjusted for exploitability and exposure in a typical KP deployment, per the
   severity model in [vulnerability-management.md](vulnerability-management.md) § 4.1.
2. **Route to POA&M.** Every confirmed finding is recorded as a weakness in the
   [POA&M](../compliance/POAM.md) (authoritative CSV: [`poam.csv`](../compliance/poam.csv)),
   mapped to its primary NIST 800-53r5 control, with an `Open` status and a scheduled
   completion date.
3. **FedRAMP remediation SLA.** Remediation timelines follow the FedRAMP Moderate /
   [SECURITY.md](../../SECURITY.md) SLAs — **Critical/High: 30 days**, **Moderate: 90 days**,
   **Low: 180 days** (SLA clock starts from the finding/report date). SLA aging is monitored
   by the existing `poam-aging.yml` workflow described in
   [vulnerability-management.md](vulnerability-management.md) § 4.3.
4. **Retest to close.** A finding is closed only when a fix is verified by **retest** (the
   assessor re-runs the exploit/scenario and confirms it no longer succeeds), or when a
   documented, validated compensating control or **AO risk-acceptance** decision is recorded
   in the [POA&M](../compliance/POAM.md). Closure evidence (retest result, PR/tag, or
   risk-acceptance rationale) is attached to the POA&M entry.

---

## 6. Independence requirement (CA-8(1))

FedRAMP requires that the penetration test be performed by an agent or team that is
**independent** of the KP development and operations teams (**CA-8(1)**, Independent
Penetration Agent or Team — typically a **3PAO** for a FedRAMP authorization).

- The internal pre-assessment review scheduled as **P12-WU-04** is an internal exercise. It
  is **useful** for early finding discovery and remediation, but it is conducted by parties
  associated with KP development/operations and therefore **does not satisfy** the CA-8(1)
  independence requirement on its own.
- The external, independent engagement **must be staffed and executed** before an
  authorization decision. As recorded in the [SAP](../compliance/assessment/SAP.md) § 7, the
  Independent Assessor / 3PAO role is **TBD — assign before assessment**; assignment and an
  **independence attestation** are prerequisites to the engagement.
- This separation also honors the broader principle that authoring and self-assessment must
  not double as the independent approval pass.

---

## 7. Control mapping

| Control | Title | How this plan addresses it |
|---|---|---|
| **CA-8** | Penetration Testing | This plan defines the scope, methodology (§ 2), RoE (§ 3), cadence (§ 4), and finding loop (§ 5) for the penetration test. Tracked in the [control matrix](../compliance/control-matrix.csv) as **Partial** (DAST baseline shipped in P11; the independent pen test is the P12 deliverable this plan governs). |
| **CA-8(1)** | Penetration Testing \| Independent Penetration Agent or Team | The independence requirement is stated in § 6: the internal P12-WU-04 review does not satisfy it; an independent assessor / 3PAO must be staffed. *(No standalone CA-8(1) row exists in the [control matrix](../compliance/control-matrix.csv) yet; CA-8(1) is the enhancement this plan operationalizes and should be reconciled into the matrix at assessment.)* |
| **SA-11** | Developer Testing and Evaluation | The pen test complements the developer security testing already in CI (unit/coverage floor, gosec, fuzz-smoke, govulncheck, Trivy) described in [secure-sdlc.md](secure-sdlc.md); pen-test scenario **K8** extends the existing fuzz targets. Matrix status **Partial**. |
| **RA-5(5)** | Vulnerability Monitoring and Scanning \| Privileged Access | The pen test exercises credentialed/least-privilege access (§ 3) against in-boundary endpoints, complementing the automated authenticated-scan posture described in [secure-sdlc.md](secure-sdlc.md) § 5.2 and [vulnerability-management.md](vulnerability-management.md). Matrix status **Partial**. |
| **SC-8** | Transmission Confidentiality and Integrity | Pen-test scenario **K5** (TLS/cipher downgrade against `:8443`) and the transport-protection checks across the HTTP/TLS surfaces in § 1.1 provide active evidence for SC-8 (residual gaps tracked in **POAM-004**). |

> Per-control status and the responsible party remain authoritative in the
> [control matrix](../compliance/control-matrix.csv); this plan does not change those values.

---

## 8. Cross-links

- [Security Assessment Plan (SAP)](../compliance/assessment/SAP.md) — assessment-wide scope, methodology, schedule, and RoE that this plan complements.
- [System Facts Sheet](../compliance/system-facts.md) — canonical components, ports, trust zones, interconnections.
- [Authorization Boundary Diagram](../compliance/diagrams/authorization-boundary.md) — the assessed boundary.
- [Interconnection Register](../compliance/interconnections.md) — `ICX-01..06`.
- [POA&M](../compliance/POAM.md) · [`poam.csv`](../compliance/poam.csv) — destination for findings.
- [Control Matrix](../compliance/control-matrix.csv) — per-control status and responsible party.
- [CRM](../compliance/CRM.md) — provider / customer / inherited responsibility split.
- [Secure SDLC](secure-sdlc.md) — DAST, fuzz, and developer-security-testing automation (complementary).
- [Vulnerability Management Procedure](vulnerability-management.md) — severity model, SLA enforcement, POA&M feed.
- [Threat Model](threat-model.md) — trust boundaries and attack surfaces feeding § 2.
- [Incident Response Plan](incident-response-plan.md) — escalation path if a test induces a safety-affecting condition.
- [SECURITY.md](../../SECURITY.md) — authoritative remediation SLAs.
- DAST automation: [`.github/workflows/dast.yml`](../../.github/workflows/dast.yml) (and `scripts/test/dast.sh`).
- FedRAMP Moderate baseline; NIST SP 800-53 Rev 5 (CA-8, CA-8(1), SA-11, RA-5(5), SC-8); OWASP WSTG; PTES.
</content>
</invoke>
