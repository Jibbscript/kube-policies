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
> (no validated FIPS module, unauthenticated planes, no NetworkPolicy, audit on `emptyDir`,
> untrustworthy CI). These are recorded in the [POA&M](../poam.csv) and remediated across phases
> P1–P12. Nothing here should be read as an authorization to operate.

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

Each NIST SP 800-53 Rev 5 control family is summarized below. Per-control status, responsible party,
implementing artifact, and remediating phase are tracked in the
[control matrix](../control-matrix.csv); the [POA&M](../poam.csv) carries open weaknesses. The
narratives below are placeholders for the assessment-grade detail to be added in the remediating
phase.

### 7.1 AC — Access Control

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.2 AT — Awareness and Training

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.3 AU — Audit and Accountability

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.4 CA — Assessment, Authorization, and Monitoring

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.5 CM — Configuration Management

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.6 CP — Contingency Planning

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.7 IA — Identification and Authentication

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.8 IR — Incident Response

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.9 MA — Maintenance

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.10 MP — Media Protection

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.11 PE — Physical and Environmental Protection

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.12 PL — Planning

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.13 PM — Program Management

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.14 PS — Personnel Security

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.15 PT — PII Processing and Transparency

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.16 RA — Risk Assessment

Implementation: see remediating phase; status tracked in ../control-matrix.csv. The RA-3
risk-assessment activity is supported by the canonical [System Threat Model (STRIDE)](../threat-model.md),
which analyzes every trust-boundary crossing (`ICX-01..06`) per component and maps each threat to
a mitigation, control ID, and (where open) a [POA&M](../poam.csv) item. RA-5 vulnerability
scanning is non-gating today and gated in P11.

### 7.17 SA — System and Services Acquisition

Implementation: see remediating phase; status tracked in ../control-matrix.csv. The SA-15 / SA-11
threat-modeling expectation (per [`CONTRIBUTING.md`](../../../CONTRIBUTING.md) §"Security Review
Process") is realized by the canonical [System Threat Model (STRIDE)](../threat-model.md), which is
re-reviewed on significant architectural change.

### 7.18 SC — System and Communications Protection

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.19 SI — System and Information Integrity

Implementation: see remediating phase; status tracked in ../control-matrix.csv

### 7.20 SR — Supply Chain Risk Management

Implementation: see remediating phase; status tracked in ../control-matrix.csv

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
