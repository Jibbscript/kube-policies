---
title: "Physical and Environmental Protection Policy (PE)"
control_family: "PE"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Physical and Environmental Protection Policy (PE) — Kube-Policies (KP)

This policy addresses the NIST SP 800-53 Rev 5 **Physical and Environmental Protection (PE)**
family for the Kube-Policies (KP) system (**FIPS-199 Moderate**; FedRAMP Moderate baseline). It
establishes the PE-1 policy artifact and records the family-level inheritance posture.

> **Allocation: CSP-INHERITED (wholly).** Kube-Policies is a Helm-deployed set of workloads in the
> `kube-policies-system` namespace (`ZONE-SYS`) running on a customer/CSP-provided Kubernetes
> cluster. It operates **no physical facilities, power, cooling, fire suppression, cabling, or
> environmental controls**. The **entire PE family (PE-1 through PE-18)** is therefore inherited
> from the **hosting CSP's** existing FedRAMP authorization. This aligns with the
> [CRM PE allocation](../CRM.md) and the `responsible_party=CSP`, `status=Inherited` rows in the
> [control matrix](../control-matrix.csv).

## Annual review

This policy is reviewed at least **annually** (next scheduled review **2027-05-29**) and whenever
the hosting CSP or the inheritance basis materially changes. Because PE is wholly inherited, the
review primarily reconfirms the CSP authorization reference and the inheritance scope. The review
is performed by the ISSO (TBD — assign before assessment) and re-approved by the Authorizing
Official (TBD — assign before assessment), consistent with PE-1.

## Inheritance basis

- **Inherited from.** The **hosting Cloud Service Provider (CSP)** — the FedRAMP-authorized
  IaaS / managed-Kubernetes provider on whose infrastructure the customer's cluster runs. The CSP's
  data centers, physical access controls, power, emergency lighting, fire protection, temperature/
  humidity controls, and water-damage protection satisfy the PE family at the facility layer.
- **Inheritance prerequisite.** The hosting CSP must hold a current **FedRAMP Moderate (or higher)
  authorization** whose authorization boundary includes the facilities and infrastructure hosting
  the customer's cluster. The customer must **cite the specific CSP authorization package** (CSP
  name, FedRAMP package ID / authorization date) in their own SSP and **confirm the inheritance
  scope** with the CSP.
- **System action.** None. Kube-Policies implements no PE control and stores no data on media it
  physically controls.
- **Customer action.** The customer's only PE action is to **document the inheritance** in their
  ATO package (see [CRM Customer Responsibilities, item 17](../CRM.md)).

## Pointer to the Customer Responsibility Matrix (CRM)

The authoritative allocation, the inheritance language, and the Customer's "document the
inheritance" action are maintained in the **[Customer Responsibility Matrix (CRM)](../CRM.md)** —
see its **PE — Physical and Environmental Protection** section and **CSP inheritance** item 17.
This PE policy and the CRM must remain consistent; if a discrepancy is found they are reconciled
together at review time.

## PE family controls (all CSP-inherited)

The full FedRAMP Moderate PE baseline is inherited from the hosting CSP. Representative controls:

| Control | Title | Allocation | Inheritance basis |
|---|---|---|---|
| **PE-1** | Policy and Procedures | CSP-Inherited (System authors this pointer artifact) | CSP facility PE program; this document points to it. |
| PE-2 | Physical Access Authorizations | CSP-Inherited | CSP data-center access program. |
| PE-3 | Physical Access Control | CSP-Inherited | CSP facility access controls. |
| PE-4 | Access Control for Transmission | CSP-Inherited | CSP cabling/distribution protection. |
| PE-5 | Access Control for Output Devices | CSP-Inherited | CSP facility controls. |
| PE-6 | Monitoring Physical Access | CSP-Inherited | CSP facility monitoring/CCTV. |
| PE-8 | Visitor Access Records | CSP-Inherited | CSP visitor logging. |
| PE-9 | Power Equipment and Cabling | CSP-Inherited | CSP power distribution. |
| PE-10 | Emergency Shutoff | CSP-Inherited | CSP facility. |
| PE-11 | Emergency Power | CSP-Inherited | CSP UPS/generator. |
| PE-12 | Emergency Lighting | CSP-Inherited | CSP facility. |
| PE-13 | Fire Protection | CSP-Inherited | CSP fire detection/suppression. |
| PE-14 | Environmental Controls | CSP-Inherited | CSP temperature/humidity control. |
| PE-15 | Water Damage Protection | CSP-Inherited | CSP facility. |
| PE-16 | Delivery and Removal | CSP-Inherited | CSP asset handling. |
| PE-17 | Alternate Work Site | CSP-Inherited / Customer org policy | CSP + customer remote-work policy. |
| PE-18 | Location of System Components | CSP-Inherited | CSP facility siting. |

Per-control status is tracked as `Inherited` with `responsible_party=CSP` in the
[control matrix](../control-matrix.csv).

## Cross-references

- [CRM](../CRM.md) — PE family allocation (CSP-Inherited, wholly) and CSP inheritance item 17.
- [control matrix](../control-matrix.csv) — PE rows (`status=Inherited`, `responsible_party=CSP`).
- [MP policy](MP-policy.md) — storage-media protection that depends on the same CSP inheritance.
- [SSP](../ssp/SSP.md) — system environment and authorization boundary.
- [system facts](../system-facts.md) — trust zones (`ZONE-EXT`/`ZONE-SYS`) and deployment model.
