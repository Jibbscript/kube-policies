# Incident Record — [INCIDENT-ID] [Short Title]

> IRM-WU-01 · Template version 0.1.0
> Copy this file to `docs/security/incidents/YYYY-MM-DD-[slug].md` and fill in every field.
> Fields marked **[REQUIRED]** must be completed before the record is closed.
> Fields marked *[if applicable]* may be left `N/A` with a brief justification.

---

## 1 Identification

| Field | Value |
|---|---|
| **Incident ID** | [e.g. INC-2026-001] **[REQUIRED]** |
| **Short title** | [one-line description] **[REQUIRED]** |
| **Severity** | [SEV1 / SEV2 / SEV3 / SEV4] **[REQUIRED]** |
| **Status** | [Open / Contained / Eradicated / Recovered / Closed] **[REQUIRED]** |
| **Detected** | [YYYY-MM-DD HH:MM UTC] **[REQUIRED]** |
| **Declared** | [YYYY-MM-DD HH:MM UTC — time IC declared incident] **[REQUIRED]** |
| **Contained** | [YYYY-MM-DD HH:MM UTC] *[if applicable]* |
| **Recovered** | [YYYY-MM-DD HH:MM UTC] **[REQUIRED before closure]** |
| **Closed** | [YYYY-MM-DD HH:MM UTC] **[REQUIRED before closure]** |
| **Total duration** | [HH:MM from declared to recovered] **[REQUIRED]** |
| **Detection source** | [Alert name / manual report / customer / automated scan] **[REQUIRED]** |
| **Affected components** | [AST-WH / AST-PM / AST-DB / AST-CRD-POL / AST-CRD-EXC / other] **[REQUIRED]** |

---

## 2 Responders

| Role | Name | Contact |
|---|---|---|
| Incident Commander | TBD — assign | |
| Ops / SRE Responder | TBD — assign | |
| Security Responder | TBD — assign | |
| Communications Lead | TBD — assign | |
| ISSO | TBD — assign | |
| System Owner / AO notified? | Yes / No / N/A | Notified at: [HH:MM UTC] |

---

## 3 Timeline

Record every significant event in chronological order. Include timestamps in UTC.

| UTC Timestamp | Actor | Event |
|---|---|---|
| YYYY-MM-DD HH:MM | [Role] | [Alert fired / Observation made / Action taken / Notification sent] |
| | | |
| | | |

---

## 4 Description

### 4.1 What happened

*Factual narrative of the incident. What was observed, what systems were affected, and what
the timeline of events looked like. No speculation — record facts and clearly label
hypotheses.*

[Fill in]

### 4.2 Root cause

*The underlying technical or process cause. Reference the specific error_type, alert name,
or configuration gap. Leave blank until confirmed; mark "Under investigation" if still open
at closure.*

[Fill in]

### 4.3 Blast radius / impact

*What was the actual security, availability, or compliance impact? Reference specific metrics
or log entries.*

- Admission requests affected: [count / N/A]
- Audit records lost or at risk: [count / N/A]
- AU-9 / AU-11 compliance impact: [Yes — describe / No]
- FedRAMP reportable: [Yes / No / Under determination]
- Data breach / PII exposure: [Yes — describe / No]
- Workloads admitted without policy evaluation (fail-open): [Yes — count / No]

---

## 5 Actions taken

### 5.1 Containment actions

| Action | Executed by | Timestamp (UTC) | Deviation from normal? |
|---|---|---|---|
| [e.g. Rolled back Policy CR to version N] | [Role] | HH:MM | [Yes — logged in POA&M / No] |
| | | | |

### 5.2 Eradication actions

| Action | Executed by | Timestamp (UTC) |
|---|---|---|
| [e.g. Fixed OPA bundle, redeployed image digest X] | [Role] | HH:MM |
| | | |

### 5.3 Recovery actions

| Action | Executed by | Timestamp (UTC) |
|---|---|---|
| [e.g. Re-enabled ValidatingWebhookConfiguration failurePolicy: Fail] | [Role] | HH:MM |
| [e.g. Confirmed kube_policies_audit_events_total{status="written"} rising] | [Role] | HH:MM |
| | | |

---

## 6 Evidence preserved

List all evidence artifacts, their location, and retention expiry.

| Artifact | Location / Reference | Retained until |
|---|---|---|
| Prometheus metric snapshots | [URL / file path] | [Date] |
| Log excerpts | [URL / file path] | [Date] |
| Audit records | [path or SIEM query] | [AU-11 retention date] |
| Alertmanager notification history | [URL] | [Date] |

---

## 7 Notifications sent

| Recipient | Method | Timestamp (UTC) | Reported as |
|---|---|---|---|
| Incident Commander | Pager | HH:MM | SEV[N] |
| ISSO | Email | HH:MM | |
| System Owner | Email / phone | HH:MM | |
| US-CERT *[if reportable]* | Portal + email | HH:MM | [Incident category] |
| FedRAMP PMO *[if reportable]* | Secure email | HH:MM | |
| Agency AO / CISO *[if reportable]* | Secure email | HH:MM | |

---

## 8 Post-incident findings

### 8.1 What went well

- [List]

### 8.2 What went poorly / gaps identified

- [List]

### 8.3 Action items

| # | Action | Owner | Due date | POA&M entry? |
|---|---|---|---|---|
| 1 | [Description] | [Role / Name] | YYYY-MM-DD | [POAM-NNN / No] |
| 2 | | | | |

### 8.4 Runbook / alert updates required

*List any runbooks or alert rules that should be updated based on this incident.*

- [ ] [Runbook / alert name] — [what needs to change]

---

## 9 Closure sign-off

| Role | Name | Date (UTC) | Signature / comment |
|---|---|---|---|
| Incident Commander | | YYYY-MM-DD | |
| ISSO | | YYYY-MM-DD | All POA&M entries opened? [Yes / No] |
| System Owner | | YYYY-MM-DD | *[Required for SEV1/SEV2]* |

---

## 10 References

- Incident Response Plan: [docs/security/incident-response-plan.md](../incident-response-plan.md)
- Applicable runbook: [docs/security/runbooks/](../runbooks/)
- POA&M: [docs/compliance/POAM.md](../../compliance/POAM.md)
- NIST SP 800-61 Rev 2; NIST SP 800-53 Rev 5 IR-4, IR-8; FedRAMP Incident Communications Procedure.
