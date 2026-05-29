---
title: "FIPS-199 / FIPS-200 Security Categorization — Kube-Policies (KP)"
control_family: "RA — Risk Assessment (RA-2 Security Categorization)"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
approval:
  categorization: "Moderate"
  approved_by_role: "System Owner (TBD — assign before assessment; see POAM-ORG-ROLES)"
  approval_date: "2026-05-29"
  concurrence_role: "Authorizing Official (TBD — assign before assessment)"
  concurrence_date: "2026-05-29"
---

# FIPS-199 / FIPS-200 Security Categorization

This document records the FIPS Publication 199 security categorization for the
Kube-Policies system (KP) and the FIPS Publication 200 minimum security
requirement that follows from it. Information types and their provisional impact
values are derived using the methodology and impact guidance of NIST SP 800-60
Volume I (methodology) and Volume II (information-type catalog). Canonical
component names, asset IDs, ports, trust zones, and interconnections are taken
verbatim from the [system facts sheet](../system-facts.md); this categorization
does not introduce new identifiers.

This categorization is reviewed at least annually (next scheduled review
2027-05-29) and re-evaluated whenever a system change materially alters the
sensitivity or criticality of the information processed.

## 1. System identification

- **System name:** Kube-Policies (Kubernetes admission-control & policy-management)
- **System abbreviation:** KP
- **Target categorization:** FIPS-199 **Moderate**
- **Standard / baseline:** NIST SP 800-53 Rev 5, FedRAMP Moderate baseline
- **Authorization boundary:** the `kube-policies-system` namespace workloads
  (`AST-WH`, `AST-PM`, `AST-DB`/`AST-SPA`, embedded `AST-OPA`) and the namespaced
  CRDs (`AST-CRD-POL`, `AST-CRD-EXC`) in trust zone `ZONE-SYS`. The
  kube-apiserver, Prometheus scraper, operators/users, and CSP infrastructure are
  outside the boundary in `ZONE-EXT`.

## 2. Information types

The system processes three information types, sourced from the
[system facts sheet](../system-facts.md) §"Information types (FIPS-199 / SP 800-60 basis)".

| ID | Information type | Description | Primary assets |
|---|---|---|---|
| IT-1 | Configuration & policy data | `Policy`/`PolicyException` CRDs, Helm values, Rego rules that govern admission decisions | `AST-CRD-POL`, `AST-CRD-EXC`, `AST-OPA`, `AST-CHART` |
| IT-2 | Admission decision audit records | Allow/deny admission decisions, requester attribution, and suppression state emitted by the audit subsystem (`internal/audit`) | `AST-WH`, `AST-PM` (`ICX-02`) |
| IT-3 | Operational metrics | Prometheus exposition (request counts, latency, error rates) on `:9090/:9091/:9092` | `AST-WH`, `AST-PM`, `AST-DB` (`ICX-03`) |

## 3. Provisional impact determination (per information type)

Impact levels (Low / Moderate / High) follow FIPS-199 definitions of the
potential adverse effect of a loss of confidentiality, integrity, or
availability. Rationale references the SP 800-60 mapping methodology: a
provisional impact is assigned by analogy to the catalog and then adjusted using
the special-factor adjustment guidance for the system's operating context (KP is
the policy-enforcement control point of a Kubernetes cluster).

### IT-1 — Configuration & policy data

| Objective | Impact | Rationale (NIST SP 800-60) |
|---|---|---|
| Confidentiality | **Low** | Policy rules and Helm values are configuration metadata, not personal or proprietary mission data. SP 800-60 Vol. II treats configuration management information as generally low-confidentiality; disclosure of which Rego constraints exist provides limited adversary advantage and no unauthorized disclosure of regulated data. Provisional Low retained (no special factor raising it). |
| Integrity | **Moderate** | Per SP 800-60 Vol. I §C.3.5.1 adjustment guidance, integrity is raised above the catalog baseline because these records are the authoritative source that drives admission allow/deny enforcement. Unauthorized modification of a `Policy`/`PolicyException` or Rego rule can silently weaken or disable cluster-wide enforcement (`spec.template.spec` blindness and exception abuse are tracked gaps), so unauthorized modification has a serious adverse effect. |
| Availability | **Moderate** | SP 800-60 special-factor adjustment: loss of policy/configuration availability degrades the ability to evaluate admission requests. Because the shipped default is **fail-closed** (`internal/config`), unavailability of policy data can block legitimate workload admission, a serious but not catastrophic adverse effect on cluster operations. |

### IT-2 — Admission decision audit records

| Objective | Impact | Rationale (NIST SP 800-60) |
|---|---|---|
| Confidentiality | **Moderate** | Audit records contain object specifications, requester attribution, and decision detail. SP 800-60 Vol. II audit/accountability information carries Moderate confidentiality where records describe security-relevant actions and could aid an attacker in reconnaissance; KP records reveal enforcement coverage and request content, warranting Moderate. |
| Integrity | **Moderate** | SP 800-60 identifies integrity as the driving objective for accountability information: audit records must be trustworthy for incident response and assessment. Undetected modification or fabrication of allow/deny records would defeat after-the-fact accountability — a serious adverse effect — so integrity is Moderate. |
| Availability | **Moderate** | Loss of audit availability impairs detection and forensic reconstruction. The current audit backend can write to an `emptyDir` (a tracked gap), increasing loss exposure; SP 800-60 adjustment raises availability to Moderate given the accountability mission of these records. |

### IT-3 — Operational metrics

| Objective | Impact | Rationale (NIST SP 800-60) |
|---|---|---|
| Confidentiality | **Low** | Prometheus exposition is aggregate operational telemetry (counts, latency, error rates) containing no regulated or personal data. SP 800-60 Vol. II maps system operational/monitoring information to Low confidentiality; the planes are currently unauthenticated (`ICX-03`), but the exposed data itself is low-sensitivity, so provisional Low is retained. |
| Integrity | **Low** | Tampered metrics could mislead operators, but per SP 800-60 the operational-monitoring catalog baseline for integrity is Low: metrics are advisory telemetry, not an enforcement or accountability source, and corruption has a limited adverse effect on the mission. |
| Availability | **Low** | Metrics support monitoring rather than enforcement; their temporary loss has a limited adverse effect because admission enforcement and audit do not depend on the metrics path. SP 800-60 operational-monitoring availability baseline of Low is retained. |

## 4. Information-type impact summary

| Information type | Confidentiality | Integrity | Availability |
|---|---|---|---|
| IT-1 Configuration & policy data | Low | Moderate | Moderate |
| IT-2 Admission decision audit records | Moderate | Moderate | Moderate |
| IT-3 Operational metrics | Low | Low | Low |

## 5. Overall system categorization (high-water mark)

FIPS-199 defines the overall system impact level by the **high-water mark** — the
highest impact value assigned to any security objective across all information
types. Taking the maximum of each column:

- Confidentiality: max(Low, Moderate, Low) = **Moderate** (driven by IT-2)
- Integrity: max(Moderate, Moderate, Low) = **Moderate** (driven by IT-1, IT-2)
- Availability: max(Moderate, Moderate, Low) = **Moderate** (driven by IT-1, IT-2)

```
SC(Kube-Policies) = {(confidentiality, MODERATE), (integrity, MODERATE), (availability, MODERATE)}
```

The high-water mark across all three objectives is **Moderate**. The overall
security categorization is therefore:

> **Overall categorization = high-water mark = MODERATE.**

This matches the FIPS-199 Moderate baseline asserted by the System Security Plan
(see [SSP](../ssp/SSP.md)) and the target categorization recorded in the
[system facts sheet](../system-facts.md).

## 6. FIPS-200 minimum security requirement

Under FIPS Publication 200, a system categorized at the Moderate impact level
must satisfy the minimum security requirements by applying the NIST SP 800-53
Rev 5 controls selected by the FedRAMP **Moderate** baseline, tailored as
documented in the SSP. Control selection, implementation status, and
responsible parties are tracked in the
[control matrix](../control-matrix.csv); open weaknesses and their remediation
phases (P1–P12) are tracked in the [POA&M](../POAM.md).

## 7. Approval and organizational action

Categorization approval is recorded in the YAML front-matter of this document.
Approval authority for the security categorization rests with the **System
Owner** role; concurrence rests with the **Authorizing Official** role
(RA-2 / CA-6).

> **Organizational action required:** The named individual filling the System
> Owner role has not yet been assigned. The front-matter approval currently
> records the *role* rather than a named person and must be updated with an
> assigned System Owner (and Authorizing Official) before the security
> assessment. This staffing action is tracked as POA&M item **POAM-ORG-ROLES**
> in the [POA&M](../POAM.md). Until that item is closed, this categorization is
> approved at the role level only.
