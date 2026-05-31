---
title: "Compliance Documentation Index — Kube-Policies (KP)"
control_family: "PL / CA — Planning & Assessment"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Compliance Documentation Index — Kube-Policies (KP)

**Current posture:** Kube-Policies is a Proof-of-Concept being driven to **FedRAMP-Moderate** (NIST SP 800-53 Rev 5, FedRAMP Moderate baseline) and **CIS** readiness; it is **not yet authorized** (no ATO) and not in production use.

This index is the entry point to the compliance evidence package. The system targets **FIPS-199 Moderate**. The [control matrix](control-matrix.csv) is the spine of the package; every artifact below cross-references it. Most controls are currently **Planned** or **Partial** — see the [POA&M](POAM.md) for open weaknesses and the phased (P1–P12) remediation plan.

> Authoritative facts (component names, asset IDs `AST-*`, ports, trust zones `ZONE-EXT`/`ZONE-SYS`, interconnections `ICX-01..06`) are pinned in [system-facts.md](system-facts.md). All other artifacts must use those IDs verbatim.

This index is reviewed at least **annually** (next review **2027-05-29**) and on any material change to the evidence package.

## Foundation

| Artifact | Description |
|---|---|
| [system-facts.md](system-facts.md) | Authoritative system facts: component names, asset IDs (`AST-*`), ports, trust zones, and interconnections. Source of truth for all other artifacts. |
| [categorization/FIPS-199.md](categorization/FIPS-199.md) | FIPS-199 / FIPS-200 security categorization (target: Moderate) and information-type analysis. |
| [security-architecture.md](security-architecture.md) | Security architecture narrative (PL-8): components, trust zones, and defense-in-depth posture. |
| [secure-configuration-baseline.md](secure-configuration-baseline.md) | Secure configuration baseline (CM-2 / CM-6): security-relevant defaults and hardening settings. |
| [crypto-module.md](crypto-module.md) | FIPS 140-3 cryptographic module (SC-13): selected module, CMVP reference, and the build/CI/runtime evidence that shipped binaries run validated crypto. |
| [crypto-standards.md](crypto-standards.md) | Approved cryptographic key strengths and signature algorithms (SC-12/SC-13/SC-17): the algorithm/key-length matrix for TLS server/client keys and certificate signing, tied to the FIPS module. |

## Boundary & Inventory

| Artifact | Description |
|---|---|
| [diagrams/authorization-boundary.md](diagrams/authorization-boundary.md) | Authorization boundary diagram: what is in-boundary (`ZONE-SYS`) versus external (`ZONE-EXT`). |
| [diagrams/data-flow.md](diagrams/data-flow.md) | Data-flow diagram across the boundary and interconnections. |
| [inventory.md](inventory.md) | Component inventory narrative (assets, images, ports). |
| [inventory.csv](inventory.csv) | Machine-readable component inventory keyed on `AST-*` asset IDs. |
| [interconnections.md](interconnections.md) | External interconnection register (`ICX-01..06`): data, sensitivity, and transport. |
| [ssp/ports-protocols-services.md](ssp/ports-protocols-services.md) | Ports, protocols, and services (PPS) register. |

## SSP & Controls

| Artifact | Description |
|---|---|
| [ssp/SSP.md](ssp/SSP.md) | System Security Plan: system description and control-implementation narratives. |
| [control-matrix.csv](control-matrix.csv) | FedRAMP-Moderate control matrix (NIST SP 800-53 Rev 5) — machine-readable spine with status, responsible party, implementing artifact, and POA&M linkage. |
| [control-matrix.md](control-matrix.md) | Human-readable summary view of the control matrix. |
| [CRM.md](CRM.md) | Control Implementation Summary / Customer Responsibility Matrix: shared, customer, and inherited responsibilities. |

## Risk & Assessment

| Artifact | Description |
|---|---|
| [POAM.md](POAM.md) | Plan of Action and Milestones (POA&M) narrative: open weaknesses and remediation milestones. |
| [poam.csv](poam.csv) | Machine-readable POA&M (`POAM-*`) with severity, remediation, milestones, and scheduled completion. |
| [threat-model.md](threat-model.md) | Canonical system threat model (STRIDE). |
| [assessment/SAP.md](assessment/SAP.md) | Security Assessment Plan: scope, methods, and schedule for independent assessment. |
| [../security/threat-model.md](../security/threat-model.md) | Pointer stub to the canonical [threat-model.md](threat-model.md). |

## Policies

| Artifact | Description |
|---|---|
| [policies/PL-policy.md](policies/PL-policy.md) | Planning policy and procedures (PL). |
| [policies/PS-policy.md](policies/PS-policy.md) | Personnel security policy (PS). |
| [policies/MP-policy.md](policies/MP-policy.md) | Media protection policy (MP). |
| [policies/PE-policy.md](policies/PE-policy.md) | Physical and environmental protection policy (PE). |
| [roles-raci.md](roles-raci.md) | ATO roles and RACI matrix (System Owner, ISSO, AO, Independent Assessor — all TBD, assign before assessment). |

## Repository-root security documents

| Artifact | Description |
|---|---|
| [../../SECURITY.md](../../SECURITY.md) | Coordinated vulnerability-disclosure (CVD) policy and remediation SLAs. |

## Planned (not yet authored)

| Artifact | Status | Description |
|---|---|---|
| DOC-WU-29 — CIS / NIST SP 800-190 self-assessment mapping | **Planned (phase P10)** | Self-assessment crosswalk mapping the system against the CIS Kubernetes Benchmark and NIST SP 800-190 (Application Container Security Guide). Forthcoming. |
