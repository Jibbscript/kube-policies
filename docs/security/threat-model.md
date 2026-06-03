---
title: "Threat Model — pointer to canonical (Kube-Policies)"
control_family: "RA / SA — Risk Assessment & System Development"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Threat Model — Kube-Policies (KP)

> **This is a pointer.** The single **canonical** system threat model lives under the compliance
> artifacts to avoid duplication:
>
> ### → [`docs/compliance/threat-model.md`](../compliance/threat-model.md)

The canonical document is the authoritative source and **fully satisfies** the threat-model
requirements; this file exists only so that `docs/security/` resolves to it. By linking to the
canonical doc, this pointer covers, for all three components — `AST-WH` (`:8443`/`:9090`),
`AST-PM` API + CRD reconcile (`:8080`/`:9091`), and `AST-DB` write-gating (`ALLOW_WRITES`,
`:8090`/`:9092`):

- a **STRIDE table per trust-boundary crossing** (`ICX-01..06`) from the
  [Data Flow Diagram](../compliance/diagrams/data-flow.md) — see canonical §§3–5;
- the **STRIDE → mitigation → control ID → POA&M** mapping (canonical §§3–7, reconciled to
  [`control-matrix.csv`](../compliance/control-matrix.csv) and [`poam.csv`](../compliance/poam.csv));
- the explicit deep dives required — **admission bypass** incl. `spec.template.spec` enforcement
  blindness (with an **attack tree**), **PolicyException abuse**, **unauthenticated API/dashboard**,
  the **plaintext decision-publish token**, and **supply-chain entry points** (canonical §6).

It realizes the **Threat Modeling** process referenced in [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
and is referenced from the [SSP](../compliance/ssp/SSP.md) (§7.16 RA, §7.17 SA) and the
Risk-Assessment procedures in the [CRM](../compliance/CRM.md) (RA — Risk Assessment).

**Annual review.** This pointer (and the canonical document it references) is reviewed at least
**annually** (next review **2027-05-29**) and whenever the architecture, authorization boundary,
or an interconnection materially changes.

Diagrams referenced by the threat model are the canonical compliance diagrams; see
[`diagrams/README.md`](diagrams/README.md), which points to
[`../compliance/diagrams/`](../compliance/diagrams/).

## References

- **Canonical threat model:** [`docs/compliance/threat-model.md`](../compliance/threat-model.md)
- [Data Flow Diagram](../compliance/diagrams/data-flow.md) · [Authorization Boundary Diagram](../compliance/diagrams/authorization-boundary.md)
- [System Facts Sheet](../compliance/system-facts.md) · [Control Matrix](../compliance/control-matrix.csv) · [POA&M](../compliance/poam.csv)
- [SSP](../compliance/ssp/SSP.md) · [CRM](../compliance/CRM.md) · [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
