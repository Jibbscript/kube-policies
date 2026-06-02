---
title: "Security Assessment Plan (SAP) — Kube-Policies (KP)"
control_family: "CA — Assessment, Authorization, and Monitoring"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Security Assessment Plan — Kube-Policies (KP)

FIPS-199 categorization: **Moderate**. Standard: **NIST SP 800-53 Rev 5**, **FedRAMP
Moderate** baseline. Assessment method semantics follow **NIST SP 800-53A Rev 5**
(Examine / Interview / Test).

This Security Assessment Plan (SAP) is a Draft scaffold for a Proof-of-Concept being driven
to assessment readiness. It defines **how** the security controls for Kube-Policies (KP) will
be assessed; it does not record results. Findings are captured separately in the Security
Assessment Report (SAR) and tracked in the [POA&M](../poam.csv). Control implementation
statuses are the spine of this effort and live in the [control matrix](../control-matrix.csv);
control narratives and responsibilities are in the [SSP](../ssp/SSP.md) and the
[Customer Responsibility Matrix (CRM)](../CRM.md).

> **Honesty note.** KP is an as-built PoC with known foundational gaps (no FIPS-validated
> cryptographic module, unauthenticated control/metrics planes, no NetworkPolicy,
> `spec.template.spec` enforcement blindness, audit on `emptyDir`, untrustworthy CI). Most
> controls are **Planned** or **Partial**; only a small set of bright spots are **Implemented**.
> This SAP assesses the system as it is, against the Moderate baseline, and is expected to
> generate findings. Remediation is sequenced across phases **P1–P12**
> (`../plans/remediation-roadmap.md`).

**Annual review.** This SAP is reviewed at least **annually** (next review **2027-05-29**) and
re-baselined upon any significant change to the system, the authorization boundary, or the
applicable baseline.

## 1. Purpose and references

The purpose of this plan is to establish the scope, methodology, schedule, and rules of
engagement for an independent security assessment of KP sufficient to support an authorization
decision under the FedRAMP Moderate baseline.

Authoritative inputs:

- [System Facts Sheet](../system-facts.md) — canonical component names, asset IDs, ports, trust zones.
- [Authorization Boundary Diagram](../diagrams/authorization-boundary.md) — the assessed boundary.
- [Data Flow Diagram](../diagrams/data-flow.md) and [Interconnection Register](../interconnections.md) — `ICX-01..06`.
- [System Inventory](../inventory.csv) — assessed assets (`AST-*`).
- [SSP](../ssp/SSP.md) and [Ports, Protocols & Services](../ssp/ports-protocols-services.md) — control narratives and PPS.
- [Control Matrix](../control-matrix.csv) — per-control status and responsible party (assessment spine).
- [CRM](../CRM.md) — customer vs. provider vs. inherited responsibility split.
- [POA&M](../poam.csv) — destination for resulting findings.
- [FIPS-199 Categorization](../categorization/FIPS-199.md) — impact basis (Moderate).

## 2. Assessment scope

The assessment scope is **bound exactly to the authorization boundary** defined in the
[Authorization Boundary Diagram](../diagrams/authorization-boundary.md). All and only the
**In-Boundary** assets within trust zone `ZONE-SYS` (the `kube-policies-system` namespace) are
in scope for direct testing. Assets in `ZONE-EXT` and **Inherited** platform controls are out of
scope for direct testing and are assessed by review of inheritance and interface only.

### 2.1 In-scope assets (`ZONE-SYS`, In-Boundary)

| Asset ID | Component | Assessed surface |
|---|---|---|
| `AST-WH` | admission-webhook | `8443/tcp` TLS 1.3 (`/validate`,`/mutate`); `9090/tcp` HTTP metrics |
| `AST-PM` | policy-manager | `8080/tcp` HTTP REST `/api/v1`; `9091/tcp` HTTP metrics |
| `AST-DB` | dashboard BFF | `8090/tcp` HTTP (SPA + `/api` + reverse-proxy → `AST-PM:8080`); `9092/tcp` HTTP metrics |
| `AST-SPA` | Svelte dashboard SPA | Static assets embedded in / served by `AST-DB:8090` |
| `AST-OPA` | OPA/Rego policy evaluator | Embedded library in `AST-WH` and `AST-PM` |
| `AST-CRD-POL` | `Policy` CRD | Schema, validation, RBAC, reconcile behavior |
| `AST-CRD-EXC` | `PolicyException` CRD | Schema, validation, RBAC, reconcile behavior |
| `AST-CHART` | Helm chart + RBAC/Services/Config | Deployed manifests, security contexts, RBAC |
| `AST-IMG-WH` / `AST-IMG-PM` / `AST-IMG-DB` | Container images | Build provenance, SBOM, vulnerability scan |

### 2.2 In-scope interconnections

`ICX-01..06` per the [Interconnection Register](../interconnections.md). Boundary-crossing
interconnections (`ICX-01`, `ICX-03`, `ICX-05`, `ICX-06`) are assessed for transport protection
and authentication at the KP-controlled endpoint; internal movements (`ICX-02`, `ICX-04`) are
assessed for transport and token handling.

### 2.3 Out of scope

- `ZONE-EXT` assets: kube-apiserver, Prometheus scraper, operators/users, and the hosting CSP
  control plane and infrastructure.
- **Inherited** controls (PE family, MA family, and the platform/host network underpinning SC-7)
  are provided by the hosting CSP. They are assessed only by reviewing the inheritance assertion
  and the KP-side interface, per the [CRM](../CRM.md); the CSP's own authorization package is the
  evidence of record for inherited controls.

### 2.4 Control scope

All control families applicable to the FedRAMP Moderate baseline are in scope. Controls marked
**Inherited** or **Customer** in the [control matrix](../control-matrix.csv) are assessed for the
correctness of the responsibility assertion rather than for KP-side implementation. Controls
marked **Not-Applicable** require an assessor-validated rationale.

## 3. Assessment methodology

Each control is assessed using one or more of the three NIST SP 800-53A methods:

- **Examine (E):** review of artifacts — code, manifests, configuration, documentation,
  pipeline definitions, generated evidence, and prior automated outputs.
- **Interview (I):** structured discussion with role holders (System Owner, ISSO, developers,
  operators) to confirm process, intent, and operation. *Role holders are TBD — assign before assessment.*
- **Test (T):** active exercise of the control — running test suites, executing validation
  scripts, sending crafted admission requests, scanning images, and inspecting live behavior.

Depth and coverage are **Moderate-baseline** appropriate. Where a control is **Planned** in the
[control matrix](../control-matrix.csv), the assessment confirms the gap and the planned
remediation phase (P1–P12) rather than asserting an absent capability.

### 3.1 Per-family assessment methods

For **each** control family in the FedRAMP Moderate baseline, at least one assessment method is
defined below. Family-level entries set the minimum; individual controls may add methods. The
authoritative per-control method and status remain the [control matrix](../control-matrix.csv).

| Family | Title | Methods | Primary scope / objects | Notes |
|---|---|---|---|---|
| **AC** | Access Control | E, I, T | `AST-CHART` RBAC, `AST-PM`/`AST-DB` authn (`8080`/`8090`), CRD RBAC | Test unauthenticated planes; expect findings (P2/P3). |
| **AT** | Awareness and Training | I, E | Role training records, contributor/onboarding docs | PoC: largely **Planned**; interview + doc review. |
| **AU** | Audit and Accountability | E, T | `internal/audit`, decision records (IT-2), `AST-WH`→`AST-PM` `ICX-02` | Test audit emission; examine `emptyDir` durability gap. |
| **CA** | Assessment, Authorization, and Monitoring | E, I | This SAP, SSP, POA&M, continuous-monitoring plan | Examine assessment artifacts; interview on ConMon cadence. |
| **CM** | Configuration Management | E, T | `AST-CHART` values/defaults, secure-config baseline, `scripts/validate/manifests.sh` | Test manifest validation; examine pinned TLS 1.3, fail-closed default. |
| **CP** | Contingency Planning | I, E | Backup/restore of CRD data, leader election in `AST-PM` | PoC: **Planned**; interview + design review. |
| **IA** | Identification and Authentication | E, T | `ICX-02` bearer token, apiserver auth to `AST-WH:8443`, OIDC target (P3) | Test token handling; examine static-bearer-token gap. |
| **IR** | Incident Response | I, E | IR process docs, alerting via Prometheus/Alertmanager | PoC: **Planned**; interview + examine alert rules. |
| **MA** | Maintenance | I, E | Patch/update process, image rebuild cadence | Largely **Inherited** (platform) + KP image maintenance; review assertion. |
| **MP** | Media Protection | E, I | CRD/data at rest (etcd), audit sink handling | **Inherited** platform storage; examine KP-side data classification. |
| **PE** | Physical and Environmental Protection | E | CSP inheritance assertion | **Inherited** from hosting CSP; examine inheritance only. |
| **PL** | Planning | E, I | SSP, this SAP, boundary, rules of behavior | Examine planning artifacts; interview System Owner/ISSO. |
| **PS** | Personnel Security | I, E | Screening/role-assignment process for KP roles | PoC: roles **TBD**; interview + doc review. |
| **RA** | Risk Assessment | E, T | Vulnerability scanning (`govulncheck`, `trivy`, `gosec`), POA&M | Test scans per [TESTING.md](../../../TESTING.md); examine risk ratings. |
| **SA** | System and Services Acquisition | E, I | SDLC, dependency management, build (`build/docker`), CI provenance | Examine supply chain; interview on SDLC; note untrustworthy-CI gap (P6). |
| **SC** | System and Communications Protection | E, T | TLS 1.3 on `AST-WH:8443`, unauthenticated metrics/REST planes, NetworkPolicy gap | Test transport; examine no-FIPS-module and no-NetworkPolicy gaps. |
| **SI** | System and Information Integrity | E, T | Admission enforcement logic, input validation, monitoring, scanning | Test enforcement (unit/integration/e2e); examine `spec.template.spec` blindness. |
| **SR** | Supply Chain Risk Management | E, T | Image provenance, SBOM, distroless base, Cosign signing (release), dependency pinning | Test image scans; examine signing/pinning (P6) and SBOM coverage. |

> Method legend: **E** = Examine, **I** = Interview, **T** = Test. Every family above lists at
> least one method.

## 4. Automated evidence sources

The assessment leverages repeatable, repo-resident automation as primary **Examine** and **Test**
evidence. Re-running these on the assessed commit produces deterministic artifacts the
Independent Assessor can attach to the SAR.

- **[TESTING.md](../../../TESTING.md)** — authoritative testing guide. Defines the evidence-bearing
  suites below and the security/static-analysis tooling.
- **Unit suite** — `go test -v ./cmd/... ./internal/... ./pkg/...` (with `-race -coverprofile`).
  Evidence for SI/AU/AC enforcement and policy-engine (`AST-OPA`) logic.
- **Integration suite** — `go test -v ./test/integration/...` (envtest). Evidence for admission
  request/response cycles, `AST-PM` API contracts, and CRD validation/storage (`ICX-01`, `ICX-04`).
- **End-to-end suite** — `go test -v ./test/e2e/...` / `./scripts/test/test-kind.sh`
  (Ginkgo + Gomega). Evidence for live policy enforcement, exceptions, and deployment behavior.
- **[`scripts/validate/manifests.sh`](../../../scripts/validate/manifests.sh)** (`make
  validate-manifests`) — offline, repeatable manifest validation: Helm lint/render, YAML syntax,
  Grafana JSON, Prometheus config/rules, Alertmanager config, and `kubeconform` schema validation.
  Evidence for CM and SC (manifest/secure-config integrity).
- **Static analysis & scanning** (per TESTING.md §Security Testing) — `gosec ./...`,
  `govulncheck ./...`, `golangci-lint run --enable=gosec`, and `trivy image|fs`. Evidence for
  RA, SA, SR, and SI.
- **Forthcoming `scripts/validate` compliance checks** — additional `scripts/validate/*` checks
  (planned, phases P1–P12) will validate compliance invariants (e.g., security-context
  conformance, RBAC least-privilege, control-matrix/inventory consistency). As these land, the
  Independent Assessor will treat their output as authoritative automated **Test** evidence and
  reference them here in the next revision.

Automated output supplements but does not replace assessor judgment; each automated artifact is
mapped to the control(s) it evidences in the SAR.

## 5. Assessment schedule

Indicative schedule; all dates and durations are placeholders pending assessor assignment and a
frozen assessment baseline (commit/tag). The schedule is re-baselined at kickoff.

| Phase | Activity | Owner role | Window (indicative) |
|---|---|---|---|
| A0 | Assessment kickoff; freeze baseline commit/tag; confirm scope vs. boundary | Independent Assessor + System Owner | Day 0 |
| A1 | Artifact intake (SSP, control matrix, boundary, inventory, CRM, POA&M) | Independent Assessor | Days 1–3 |
| A2 | Examine: documentation, manifests, code, pipeline; run automated evidence sources | Independent Assessor | Days 3–8 |
| A3 | Interview: System Owner, ISSO, developers, operators (TBD — assign) | Independent Assessor | Days 6–9 |
| A4 | Test: execute unit/integration/e2e suites, validation scripts, scans, live probes | Independent Assessor | Days 8–14 |
| A5 | Analysis; draft findings; severity and risk rating | Independent Assessor | Days 14–17 |
| A6 | Draft SAR review with System Owner/ISSO; provisional POA&M items | Independent Assessor + System Owner | Days 17–19 |
| A7 | Final SAR delivery; POA&M ([../poam.csv](../poam.csv)) updated | Independent Assessor | Day 20 |

Annual reassessment and continuous monitoring (CA family) follow authorization; significant
changes trigger a delta assessment.

## 6. Rules of engagement (ROE)

The following ROE govern conduct of the assessment. They are confirmed and signed at kickoff (A0)
by the Independent Assessor, the System Owner, and the Authorizing Official.

- **Environment.** Testing is performed against a dedicated, non-production assessment
  environment (e.g., a Kind/k3s cluster per [TESTING.md](../../../TESTING.md)) deployed from the
  frozen baseline. No assessment activity is performed against production tenants.
- **Authorization to test.** Active testing (admission probes, scans, fault injection) requires
  written authorization captured in the signed ROE. Testing is confined to In-Boundary `ZONE-SYS`
  assets; `ZONE-EXT` and **Inherited** assets are **not** to be actively tested.
- **Boundaries.** No testing of the hosting CSP control plane/infrastructure, the kube-apiserver
  internals, or any tenant outside the KP boundary. Inherited controls are evidenced by the CSP
  authorization package, not by KP-side testing.
- **Data handling.** Only synthetic/test data is used. Any decision/audit records (IT-2) or CRD
  data (IT-1) collected as evidence are treated as **Moderate** and stored in the assessment
  evidence repository with access restricted to the assessment team.
- **Destructive testing.** Denial-of-service and destructive tests are prohibited unless
  explicitly authorized in the ROE and scheduled in a maintenance window.
- **Credentials and access.** The assessor is granted least-privilege, time-boxed access to the
  assessment environment and read access to the repository at the frozen baseline.
- **Communications and escalation.** A named point of contact (System Owner, TBD — assign) is
  available during test windows. Any safety-affecting or out-of-scope condition halts testing
  and is escalated immediately.
- **Evidence integrity.** All automated outputs are captured with the commit hash, tool versions,
  and timestamps to ensure reproducibility.

## 7. Roles and responsibilities

Named roles are **not yet staffed**; role titles are used with "TBD — assign before assessment".
Do not infer individuals. See the [control matrix](../control-matrix.csv) and [CRM](../CRM.md)
for the responsible-party split.

| Role | Responsibility in this assessment | Assignment |
|---|---|---|
| **Independent Assessor** | Plans, executes, and reports the assessment independently of the development/operations team; owns the SAP, SAR, and assessment evidence; must be organizationally independent of KP system development and operation. | **TBD — assign before assessment** |
| **Authorizing Official (AO)** | Approves this SAP and the ROE; renders the authorization decision based on the SAR and POA&M. | Authorizing Official (TBD — assign) |
| **System Owner** | Provides artifacts, environment, and access; primary assessment point of contact. | System Owner (TBD — assign) |
| **ISSO** | Supports evidence collection; maintains control matrix and POA&M; coordinates remediation. | ISSO (TBD — assign before assessment) |
| **Developers / Operators** | Subject-matter interviewees for AC/AU/CM/SC/SI/SA/SR controls and operational processes. | TBD — assign before assessment |

> **Independence requirement.** The **Independent Assessor** must be independent of the KP
> development and operations teams. For this PoC the role is **TBD — assign before assessment**;
> assignment and an independence attestation are prerequisites to A0 (kickoff).

## 8. Cross-links

- [Control Matrix](../control-matrix.csv) — per-control status, responsible party, implementing artifact.
- [SSP](../ssp/SSP.md) — system description and control narratives.
- [CRM](../CRM.md) — customer/provider/inherited responsibility split.
- [POA&M](../poam.csv) — findings and remediation tracking (destination for SAR results).
- [Authorization Boundary Diagram](../diagrams/authorization-boundary.md) — assessed boundary.
- [System Facts Sheet](../system-facts.md) — canonical IDs, ports, zones.
