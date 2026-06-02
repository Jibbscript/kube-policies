---
title: "POA&M Item Template and Specification — Kube-Policies (KP)"
control_family: "CA — Assessment, Authorization, and Monitoring"
controls: "CA-5, PM-4, RA-5"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# POA&M Item Template and Specification — Kube-Policies (KP)

This document defines the **required fields** for a Plan of Action and Milestones (POA&M)
item in the Kube-Policies system (KP), implementing **NIST SP 800-53 Rev 5** controls
**CA-5** (Plan of Action and Milestones), **PM-4** (Plan of Action and Milestones Process),
and **RA-5** (Vulnerability Scanning) under the **FedRAMP Moderate** baseline.

The authoritative POA&M register is [docs/compliance/POAM.md](../compliance/POAM.md) and
its companion CSV [docs/compliance/poam.csv](../compliance/poam.csv). The vulnerability
tracking issue form
[`.github/ISSUE_TEMPLATE/vulnerability.yml`](../../.github/ISSUE_TEMPLATE/vulnerability.yml)
is the GitHub Issues entry point for new vulnerability findings. The
[vulnerability management procedure](vulnerability-management.md) defines the triage
workflow that feeds items into this system.

---

## 1 Field reference

The table below defines every required and optional field for a POA&M item. Fields marked
**Required** must be populated before a new item is accepted into the register. The field
names align with both the `docs/compliance/POAM.md` markdown table and the
`docs/compliance/poam.csv` CSV schema.

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | Required | String (`POAM-NNN`) | Stable, sequential identifier. Never reused once assigned, even if the item is closed. Next available ID is one above the highest current ID in `poam.csv`. |
| `control` | Required | String (e.g. `RA-5`) | Primary NIST SP 800-53 Rev 5 control the weakness affects. Must exist as a row in [control-matrix.csv](../compliance/control-matrix.csv). Related controls may be noted in the weakness description. |
| `weakness` | Required | String (prose) | Concise description of the weakness: what is absent or broken, why it is a risk, and which component(s) are affected. |
| `source` | Required | String | How the weakness was discovered: scanner name and run date (e.g. `Trivy fs 2026-06-02`), manual review, external report reference (CVE, advisory URL), or analysis artifact path (e.g. `.omc/research/fedramp-cis-gap-analysis.json`). |
| `severity` | Required | Enum: `Critical \| High \| Moderate \| Low` | Assessor-facing weakness severity assigned at triage using CVSS v3.1 base score, adjusted for exploitability and exposure. See §2 for assignment guidance. |
| `risk_rating` | Required | Enum: `Critical \| High \| Moderate \| Low` | Residual risk after accounting for any partial mitigations or compensating controls. May differ from `severity` when a partial fix has landed. Governs urgency of the open weakness. |
| `discovery_date` | Required | `YYYY-MM-DD` | Date the weakness was first identified: scan date for automated findings, disclosure-acknowledgement date for external reports. The SLA clock starts from this date. |
| `sla_due_date` | Required | `YYYY-MM-DD` | Remediation deadline, derived from `severity` and `discovery_date` per the SLA table in §2. Must also appear as `due: YYYY-MM-DD` in the body of the linked vulnerability tracking issue so `poam-aging.yml` can parse it. |
| `owner` | Required | String (role title or GitHub username) | Person or team responsible for driving remediation to closure. Use role titles (e.g. "ISSO (TBD)") until roles are staffed; replace with GitHub username when assigned. |
| `milestone` | Required | String | Remediation phase, sprint, or release target. For phased-program items, use the phase identifier from the Production Readiness Plan (e.g. `P11`). For issue-driven items, use the GitHub milestone or release (e.g. `v0.12.0`). |
| `status` | Required | Enum (see §3) | Current lifecycle state of the item. |
| `remediation_evidence` | Required at closure | Prose + links | Steps taken or planned. At closure: PR link(s), patch version, advisory URL, or risk-acceptance rationale. Until closure: description of the planned fix and compensating controls if any. |
| `cve` | Optional | String (e.g. `CVE-2024-12345` or `GO-2024-XXXX`) | CVE identifier or advisory URL if applicable. Leave blank for non-CVE weaknesses. |
| `affected_component` | Optional | String | Specific component, image, or module affected (e.g. `admission-webhook`, `go.mod (stdlib)`, `charts/kube-policies`). |
| `poam_issue_link` | Optional | URL | Link to the GitHub vulnerability tracking issue created for this item. |
| `notes` | Optional | Prose | Any additional context: compensating controls in place, partial-remediation progress, assessor notes. |

---

## 2 Severity-to-SLA mapping

Severity is assigned at triage using CVSS v3.1 base score as the primary input, adjusted for
exploitability and exposure in a typical KP deployment. The SLA clock starts from
`discovery_date`. These values are authoritative in
[SECURITY.md](../../SECURITY.md) — this table must always match.

| Severity | CVSS (guideline) | SLA (from discovery date) |
|---|---|---|
| **Critical** | 9.0 – 10.0 | **30 days** |
| **High** | 7.0 – 8.9 | **30 days** |
| **Moderate** | 4.0 – 6.9 | **90 days** |
| **Low** | 0.1 – 3.9 | **180 days** |

Where a fix cannot land within the SLA window, the slippage and its justification are
recorded in `remediation_evidence`, the `milestone` is updated, and the System Owner is
notified. The item remains Open with a revised `sla_due_date` reflecting the approved
extension.

---

## 3 Status lifecycle

| Status | Meaning |
|---|---|
| `open` | Weakness confirmed; remediation in progress or not yet started. |
| `in-progress` | Active remediation work underway (PR open, fix in development). |
| `pending-verification` | Fix implemented; awaiting CI confirmation or assessor verification. |
| `remediated` | Fix released and verified; closure evidence recorded. Item may be closed in the register. |
| `accepted-risk` | Weakness acknowledged; risk formally accepted by System Owner and AO with documented rationale. Requires ISSO and System Owner sign-off; AO notification required for Critical/High items. Remains in register with `risk_rating` reflecting accepted residual risk. |
| `false-positive` | Finding determined to be a false positive. Justification must be recorded in `remediation_evidence`. Item may be closed; suppression register entry added if applicable (see §5 of the vulnerability management procedure). |

---

## 4 POA&M item template (Markdown)

Copy the block below to create a new POA&M item entry in `docs/compliance/POAM.md`:

```markdown
### POAM-NNN — [Brief weakness title]

| Field | Value |
|---|---|
| **ID** | POAM-NNN |
| **Control** | RA-5 (primary); SI-2, CA-5 (related) |
| **Weakness** | [Concise description of what is absent or broken and why it is a risk] |
| **Source** | [Tool name, run date, or analysis reference] |
| **CVE / Advisory** | [CVE-XXXX-NNNNN or advisory URL, or N/A] |
| **Affected component** | [Component name] |
| **Severity** | High |
| **Risk rating** | Moderate |
| **Discovery date** | YYYY-MM-DD |
| **SLA due date** | YYYY-MM-DD (High = discovery + 30 days) |
| **Owner** | [Role title (TBD) or @github-username] |
| **Milestone** | [P11 or v0.X.Y or Sprint N] |
| **Status** | open |
| **Tracking issue** | #NNN |
| **Remediation evidence** | [Planned fix description. At closure: PR #NNN, patch vX.Y.Z, advisory URL.] |
| **Notes** | [Compensating controls in place; partial-remediation progress; assessor notes.] |
```

---

## 5 Vulnerability tracking issue to POA&M mapping

The [vulnerability issue form](../../.github/ISSUE_TEMPLATE/vulnerability.yml) is the
primary intake channel for new vulnerability findings from automated scanners and external
reports. The fields in the issue form map directly to POA&M fields as follows:

| Issue form field | POA&M field | Notes |
|---|---|---|
| `Vulnerability ID` | `id` (assigned after triage) | The issue form uses an internal ID (e.g. `VULN-2026-001`); the POAM-NNN is assigned when the item enters the register |
| `Affected Component` | `affected_component` | |
| `CVE / Advisory` | `cve` | |
| `Severity` (dropdown) | `severity` | Matches exactly: `critical \| high \| moderate \| low` |
| `Control ID` | `control` | |
| `Discovery Date` | `discovery_date` | |
| `SLA Due Date` (format: `due: YYYY-MM-DD`) | `sla_due_date` | The `due:` prefix is **required** exactly as shown — `poam-aging.yml` parses this literal pattern from the issue body to compute SLA breach; incorrect format causes the item to fall back to discovery-date + severity-window |
| `Owner` | `owner` | |
| `Milestone / Sprint` | `milestone` | |
| `Status` (dropdown) | `status` | |
| `Remediation Notes` | `remediation_evidence` | |

### 5.1 How `poam-aging.yml` computes aging

`poam-aging.yml` (`.github/workflows/poam-aging.yml`) runs every Monday at 07:00 UTC. For
each open GitHub Issue labelled `vuln`:

1. It looks for a `due: YYYY-MM-DD` pattern in the issue body. If found, that date is the
   SLA due-date for breach computation.
2. If no `due:` field is present, it falls back to `issue.created_at` plus the SLA window
   for the severity derived from the issue's labels (`critical`/`high`→30d,
   `moderate`/`medium`→90d, `low`→180d).
3. It computes `ageDays` (days since creation) and `overDays` (days past the SLA due-date).
4. Items where `today > slaDue` are marked `BREACHED` in the weekly aging report.
5. A Slack notification is posted to `#kube-policies-ci` when `breached_count > 0`
   (guarded by `secrets.SLACK_WEBHOOK` availability).

This means the `due: YYYY-MM-DD` field in the issue body is load-bearing for accurate SLA
tracking. Always set it at issue creation time using the SLA table in §2.

### 5.2 How code-scanning alerts feed POA&M items

GitHub code-scanning alerts (from Trivy SARIF, govulncheck SARIF, gosec SARIF, CodeQL)
appear in the repository **Security** tab → **Code scanning**. When a new alert is
confirmed as a true positive requiring a POA&M entry:

1. The ISSO reviews the alert in the Security tab.
2. A vulnerability tracking issue is opened via the issue form; the `Source` field
   references the scanner and alert URL.
3. The tracking issue number is added as a cross-reference in the code-scanning alert
   (via the alert's "Create issue" or manual comment).
4. The POAM-NNN is allocated in `poam.csv` and `POAM.md` with the tracking issue linked
   in `poam_issue_link`.

The Security-tab alert is the raw finding; the tracking issue is the triage and remediation
record; the POA&M entry is the compliance artifact. All three must be consistent.

---

## 6 POA&M CSV schema

`docs/compliance/poam.csv` is the system-of-record CSV. Its fixed header is:

```
poam_id,weakness,source,control_id,severity,remediation,milestones,scheduled_completion,status,risk_rating
```

When adding a new item, all required cells must be populated. The `scheduled_completion`
cell must contain a real date (`YYYY-MM-DD`). The `control_id` cell must reference a row in
`control-matrix.csv`. `severity` and `risk_rating` must each be exactly one of
`Critical | High | Moderate | Low`.

---

## 7 References

- POA&M register: [docs/compliance/POAM.md](../compliance/POAM.md)
- POA&M CSV: [docs/compliance/poam.csv](../compliance/poam.csv)
- Control matrix: [docs/compliance/control-matrix.csv](../compliance/control-matrix.csv)
- Vulnerability management procedure:
  [docs/security/vulnerability-management.md](vulnerability-management.md)
- Vulnerability tracking issue form:
  [.github/ISSUE_TEMPLATE/vulnerability.yml](../../.github/ISSUE_TEMPLATE/vulnerability.yml)
- POA&M aging workflow:
  [.github/workflows/poam-aging.yml](../../.github/workflows/poam-aging.yml)
- SECURITY.md (authoritative SLA source): [SECURITY.md](../../SECURITY.md)
- NIST SP 800-53 Rev 5 (CA-5, PM-4, RA-5); FedRAMP Moderate baseline
