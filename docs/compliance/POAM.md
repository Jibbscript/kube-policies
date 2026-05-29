---
title: "Plan of Action and Milestones (POA&M)"
control_family: "CA — Assessment, Authorization, and Monitoring"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Plan of Action and Milestones (POA&M) — Kube-Policies (KP)

This POA&M is the authoritative register of open security weaknesses for the Kube-Policies
system and the remediation plan that drives them to closure (NIST SP 800-53 Rev 5 **CA-5**,
**PM-4**). It is the human-readable companion to the machine-readable
[poam.csv](poam.csv) and is the binding source for the `poam_id` references carried in the
[control matrix](control-matrix.csv) `poam_id` column. The system categorization target is
FIPS-199 **Moderate** under the NIST SP 800-53 Rev 5 / FedRAMP Moderate baseline.

> **Provenance.** Every row is seeded from the grounded, code-level
> `kube-policies FedRAMP/CIS gap analysis 2026-05-29`
> (`.omc/research/fedramp-cis-gap-analysis.json`, 12 dimensions) and its executive summary.
> Each weakness maps to a NIST 800-53r5 control that exists in the
> [control matrix](control-matrix.csv) and to a remediating phase (P0–P12) of the
> [Production Readiness Plan](../../.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md).

This is a PoC being driven to ATO readiness. The honest posture is that **most controls are
Planned or Partial**; the POA&M below tracks the open weaknesses that must close before a
FedRAMP-Moderate authorization decision. This register is reviewed at least **annually**
(next review 2027-05-29) and on every material change, in addition to the monthly
continuous-monitoring cadence described under [How to maintain](#how-to-maintain-this-poam).

## How to read this register

- **poam_id** — stable identifier (`POAM-NNN`); never reused once retired.
- **control_id** — the primary NIST 800-53r5 control the weakness affects; this value must
  exist as a row in [control-matrix.csv](control-matrix.csv). Related controls are named in
  the weakness/remediation prose.
- **severity** — assessor-facing weakness severity: `Critical | High | Moderate | Low`.
- **risk_rating** — residual risk after accounting for any compensating controls; may differ
  from severity where a partial mitigation exists.
- **remediation** — the fixing phase and work-unit family from the
  [Production Readiness Plan](../../.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md) (P0–P12).
- **scheduled_completion** — target close date, planned by remediating phase across 2026.
- **status** — lifecycle state; all rows currently `Open`.

## Severity rollup (current)

| Severity | Open items |
|---|---|
| Critical | 9 |
| High | 17 |
| Moderate | 10 |
| Low | 2 |
| **Total** | **38** |

The nine **Critical** items are the ATO-blockers: no FIPS-validated cryptographic module
(SC-13), unauthenticated management/enforcement planes (IA-2 / AC-3), plaintext HTTP on the
management plane (SC-8), the over-broad shared ServiceAccount (AC-6), the absent NetworkPolicy
boundary (SC-7), the policy-engine `spec.template.spec` enforcement blindness (CM-6), absent
audit tamper-evidence on `emptyDir` storage (AU-9), and the untrustworthy CI Go-version skew
(SA-11). None of these can be open at the authorization decision.

## Summary table

| POA&M | Control | Severity | Risk | Phase | Scheduled | Weakness |
|---|---|---|---|---|---|---|
| POAM-001 | SC-13 | Critical | High | P2 | 2026-08-15 | No FIPS 140-2/3 validated cryptographic module |
| POAM-002 | IA-2 | Critical | High | P3 | 2026-09-15 | Unauthenticated management & enforcement planes |
| POAM-003 | AC-3 | Critical | High | P3 | 2026-09-15 | No application-layer authorization model |
| POAM-004 | SC-8 | Critical | High | P4 | 2026-10-15 | Plaintext HTTP on the management plane |
| POAM-005 | IA-3 | High | High | P3 | 2026-09-15 | Webhook accepts any client (no apiserver mTLS) |
| POAM-006 | AC-6 | Critical | High | P3 | 2026-09-15 | Over-broad shared ServiceAccount / ClusterRole |
| POAM-007 | SC-7 | Critical | High | P4 | 2026-10-15 | No NetworkPolicy (no default-deny boundary) |
| POAM-008 | CM-6 | Critical | High | P10 | 2026-10-31 | Policy-engine `spec.template.spec` blindness |
| POAM-009 | SI-10 | High | Moderate | P10 | 2026-10-31 | Unvalidated Rego in CRD; no compile check |
| POAM-010 | AU-9 | Critical | High | P7 | 2026-11-30 | No audit tamper-evidence; emptyDir storage |
| POAM-011 | AU-4 | High | Moderate | P7 | 2026-11-30 | Audit retention/capacity not enforced |
| POAM-012 | AU-6 | High | Moderate | P7 | 2026-11-30 | No SIEM forwarding / audit reduction |
| POAM-013 | AU-3 | Moderate | Moderate | P7 | 2026-11-30 | Incomplete audit source/identity attribution |
| POAM-014 | SA-11 | Critical | High | P1 | 2026-07-15 | Untrustworthy CI from Go-version skew |
| POAM-015 | SR-4 | High | High | P6 | 2026-11-15 | Signing theater — no OIDC, no SLSA provenance |
| POAM-016 | CP-9 | High | Moderate | P8 | 2026-12-15 | No automated/verified backup of policy state |
| POAM-017 | CP-10 | High | Moderate | P8 | 2026-12-15 | No DR/HA for the fail-closed gatekeeper |
| POAM-018 | PS-2 | High | Moderate | P0 | 2026-06-30 | ATO roles unassigned (System Owner/ISSO/AO) |
| POAM-019 | CA-2 | High | Moderate | P12 | 2026-12-31 | Control matrix not reconciled to FedRAMP OSCAL |
| POAM-020 | IA-5 | High | Moderate | P3 | 2026-09-15 | Single shared static inter-service token |
| POAM-021 | SC-28 | High | Moderate | P2 | 2026-08-15 | No encryption of secrets at rest |
| POAM-022 | SC-12 | Moderate | Moderate | P2 | 2026-08-15 | No PKI/key-management lifecycle |
| POAM-023 | CM-2 | High | Moderate | P5 | 2026-11-01 | No digest-pinned images / config baseline |
| POAM-024 | CM-7 | High | Moderate | P5 | 2026-11-01 | Chart less hardened than base manifest |
| POAM-025 | RA-5 | High | Moderate | P11 | 2026-12-31 | Vulnerability scanning does not gate the build |
| POAM-026 | SI-2 | Moderate | Moderate | P11 | 2026-12-31 | No flaw-remediation program / SLAs |
| POAM-027 | SC-5 | Moderate | Low | P4 | 2026-10-15 | No DoS / resource-availability protection |
| POAM-028 | AU-12 | Moderate | Moderate | P7 | 2026-11-30 | No system-wide time-correlated audit trail |
| POAM-029 | AU-5 | Moderate | Low | P9 | 2026-12-31 | No alerting on audit-processing failure |
| POAM-030 | SI-4 | High | Moderate | P9 | 2026-12-31 | No detection/monitoring safety net |
| POAM-031 | IR-8 | High | Moderate | P9 | 2026-12-31 | No Incident Response Plan or runbooks |
| POAM-032 | CA-7 | Moderate | Low | P9 | 2026-12-31 | No continuous-monitoring strategy / SLOs |
| POAM-033 | SR-3 | Moderate | Moderate | P6 | 2026-11-15 | Supply-chain governance gaps (SECURITY.md, SCRM) |
| POAM-034 | SA-15 | Moderate | Moderate | P11 | 2026-12-31 | No secure-SDLC quality gates |
| POAM-035 | CM-14 | High | Moderate | P6 | 2026-11-15 | No admission-time image signature verification |
| POAM-036 | AC-12 | Low | Low | P3 | 2026-09-15 | No dashboard session management |
| POAM-037 | CM-8 | Moderate | Low | P10 | 2026-10-31 | No customer-posture inventory enforcement |
| POAM-038 | AU-7 | Low | Low | P7 | 2026-11-30 | No audit reduction/report generation |

The authoritative, parseable record (full weakness text, remediation detail, milestones, and
source) is [poam.csv](poam.csv). Where this table and the CSV disagree, **the CSV governs**.

## How to maintain this POA&M

The CSV at [poam.csv](poam.csv) is the system of record; this Markdown file is a derived
summary. To keep the two consistent and assessor-grade:

1. **Header is fixed.** `poam.csv` must keep the exact header
   `poam_id,weakness,source,control_id,severity,remediation,milestones,scheduled_completion,status,risk_rating`.
   Do not add, rename, or reorder columns.
2. **Required cells.** `severity` (one of `Critical|High|Moderate|Low`) and
   `scheduled_completion` (a real date) must never be blank. `control_id` must reference a row
   that exists in [control-matrix.csv](control-matrix.csv).
3. **Adding a weakness.** Allocate the next sequential `POAM-NNN` (never reuse a retired id),
   cite the originating analysis in `source`, map it to its primary `control_id` and remediating
   phase (P0–P12), and set a phase-aligned `scheduled_completion`. Then add a matching summary
   row above.
4. **Closing a weakness.** When remediation is verified, change `status` from `Open` to
   `Completed` (record the closure evidence in the assessment record), keep the row for audit
   history, and reflect the closure in the [control matrix](control-matrix.csv) by moving the
   corresponding control to `Implemented` and clearing or updating its `poam_id`.
5. **Two-way traceability.** Every `Open` weakness should be reachable from its control's
   `poam_id` cell in [control-matrix.csv](control-matrix.csv); every `Planned`/`Partial`
   control with residual risk should point at a `POAM-NNN` here.
6. **Cadence.** Review under continuous monitoring **monthly** (re-rank severity/risk, advance
   milestones, escalate slipped `scheduled_completion` dates) and re-baseline this register at
   least **annually** (next review 2027-05-29). FedRAMP remediation timelines —
   Critical/High 30 days, Moderate 90 days, Low 180 days — apply once the SLA-bound
   vulnerability-management program (POAM-025 / POAM-026) is operational.
7. **Validation.** Before commit, confirm the CSV parses with the required columns and that no
   `severity` or `scheduled_completion` cell is blank (e.g.,
   `python3 -c "import csv;rows=list(csv.reader(open('docs/compliance/poam.csv')));assert all(r[4] and r[7] for r in rows[1:])"`).

## Roles and ownership

Named ATO roles are not yet staffed. Until **POAM-018** closes, treat the following as
**TBD — assign before assessment**: **System Owner** (owns this register), **ISSO**
(maintains it under continuous monitoring), **Authorizing Official** (accepts residual risk),
and **Independent Assessor / 3PAO** (validates closures). Do not record real individuals until
they are formally designated.

## Related artifacts

- [poam.csv](poam.csv) — authoritative, machine-readable POA&M register.
- [control matrix](control-matrix.csv) — control implementation status spine; carries the
  `poam_id` back-references to this register.
- [System Security Plan](ssp/SSP.md) — system description and control narratives.
- [Customer Responsibility Matrix](CRM.md) — control allocation (system / CSP-inherited /
  customer / shared).
- [Component inventory](inventory.csv) · [inventory.md](inventory.md) — `AST-*` assets.
- [System facts sheet](system-facts.md) — authoritative component, port, and trust-zone IDs.
- [Production Readiness Plan](../../.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md) — the
  phased remediation (P0–P12) that the `remediation` column references.
