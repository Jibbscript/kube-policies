---
title: "Media Protection Policy (MP)"
control_family: "MP"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Media Protection Policy (MP) — Kube-Policies (KP)

This policy addresses the NIST SP 800-53 Rev 5 **Media Protection (MP)** family for the
Kube-Policies (KP) system (**FIPS-199 Moderate**; FedRAMP Moderate baseline). It establishes the
MP-1 policy artifact and governs the protection of **exported audit and policy data** produced by
the system. The authoritative responsibility split is in the [CRM](../CRM.md) (MP family) and the
per-control status is in the [control matrix](../control-matrix.csv).

> **Scope note.** Kube-Policies handles **no removable or physical media**. Protection of the
> underlying **storage media** (disks backing etcd, node volumes, and any object storage) is
> **CSP-inherited** from the hosting CSP's FedRAMP authorization. The System portion of MP is
> limited to governing **data the system exports** — namely the admission decision audit records
> (information type **IT-2**) and policy/configuration data (**IT-1**) — once it leaves the
> authorization boundary.

## Annual review

This policy is reviewed at least **annually** (next scheduled review **2027-05-29**) and whenever
the audit-export mechanism, the storage backend, or the hosting CSP materially changes. The review
is performed by the ISSO (TBD — assign before assessment) and re-approved by the Authorizing
Official (TBD — assign before assessment), consistent with MP-1.

## What media this policy governs

- **In scope (System data export).** Admission **decision audit records** (IT-2; `internal/audit`)
  and **policy/configuration data** (IT-1: `Policy`/`PolicyException` CRDs `AST-CRD-POL`/
  `AST-CRD-EXC`, Helm values, Rego rules) when **exported** from the system — e.g., audit forwarded
  to a SIEM/log store (P7) or a configuration backup taken by the customer.
- **CSP-inherited (storage media).** The physical/virtual storage media that back etcd
  (`ICX-06`), node ephemeral volumes (today audit writes to `emptyDir` — a tracked durability gap),
  and any persistent volumes are media owned and protected by the **hosting CSP**.
- **Not applicable.** Removable media (USB, optical, tape) and printed/physical media — the system
  neither reads nor writes any.

## MP-1 — Policy and Procedures

- **Requirement.** Maintain and disseminate a media-protection policy and procedures; review them
  periodically.
- **Allocation.** **System-authored policy; storage-media protection CSP-inherited; organizational
  tailoring Customer-Responsibility.** This document is the System's MP-1 artifact. The customer
  tailors it into their organizational MP policy.
- **Status:** Planned → P0/P12 (authored in P0; finalized at assessment in P12). See
  [control matrix](../control-matrix.csv).

## MP-2 — Media Access

- **Requirement.** Restrict access to media to authorized personnel/roles.
- **Application.** For **exported audit/policy data**, access is restricted by the access controls
  of the **destination** (SIEM, log store, backup repository) — Customer-operated. For the
  underlying **storage media**, access restriction is **CSP-inherited**.
- **Allocation.** Customer-Responsibility (exported data) / CSP-Inherited (storage media).
- **Status:** Planned (Customer) / Inherited (CSP).

## MP-3 — Media Marking

- **Requirement.** Mark media to indicate handling/distribution limits, with organization-defined
  exemptions.
- **Application.** Exported audit/policy data carries **Moderate** sensitivity (IT-1/IT-2) and
  should be marked/labeled accordingly by the customer's data-handling process at the destination.
- **Allocation.** Customer-Responsibility.
- **Status:** Planned (Customer).

## MP-4 / MP-5 — Media Storage and Transport

- **Requirement.** Physically control and securely store media, and protect/track media during
  transport.
- **Application.** **CSP-inherited** for the physical storage media. For exported data in transit,
  protection is the in-transit cryptography of the export path (audit-forwarding TLS lands in P7;
  see SC family in the [CRM](../CRM.md)).
- **Allocation.** CSP-Inherited (storage media) / Shared (System provides in-transit protection on
  export; Customer operates the destination).
- **Status:** Inherited (CSP) / Planned (System export path → P7).

## MP-6 — Media Sanitization

- **Requirement.** Sanitize media before disposal or reuse, using mechanisms commensurate with the
  data sensitivity.
- **Application.** Sanitization and secure disposal of the **underlying storage media** (decommissioned
  disks backing etcd and node volumes) is **wholly CSP-inherited** from the hosting CSP's
  FedRAMP-authorized media-sanitization program. Kube-Policies performs no media disposal.
- **Allocation.** **CSP-Inherited.**
- **Status:** Inherited (CSP).

## MP-7 — Media Use

- **Requirement.** Restrict or prohibit the use of specified media types on the system.
- **Application.** The system uses no removable media; this is effectively satisfied by
  architecture. Cluster-/node-level removable-media restriction is Customer-Responsibility.
- **Allocation.** Customer-Responsibility (cluster/node) — Not-Applicable to the shipped product.
- **Status:** Customer / Not-Applicable (product).

## Cross-references

- [CRM](../CRM.md) — MP family allocation (Customer-Responsibility / CSP-Inherited; System
  provides MP-1 only).
- [control matrix](../control-matrix.csv) — per-control MP status and responsible party.
- [PE policy](PE-policy.md) — physical/environmental controls that underpin storage-media
  protection (CSP-inherited).
- [POA&M](../poam.csv) — audit durability/forwarding gap (audit on `emptyDir` → P7).
- [system facts](../system-facts.md) — information types IT-1/IT-2 and interconnection identifiers.
