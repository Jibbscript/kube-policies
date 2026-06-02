---
title: "Audit and Accountability Policy (AU) — Kube-Policies (KP)"
control_family: "AU — Audit and Accountability"
controls: "AU-1, AU-2, AU-3, AU-3(1), AU-4, AU-5, AU-6, AU-7, AU-8, AU-9, AU-9(2), AU-11, AU-12, AU-12(1), SI-12"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Audit and Accountability Policy — Kube-Policies (KP)

This policy establishes the Audit and Accountability requirements for the Kube-Policies system (KP),
categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate** baseline). It
implements control **AU-1 (Policy and Procedures)** and anchors the AU controls that govern what KP
audits, how audit records are structured and attributed, and how they are retained, protected, and
reviewed: **AU-2, AU-3 / AU-3(1), AU-4, AU-5, AU-6, AU-7, AU-8, AU-9 / AU-9(2), AU-11, AU-12 /
AU-12(1)**, and **SI-12**. It is the AU-family anchor; the operational steps live in the companion
[AU procedures](../procedures/AU-procedures.md), and the per-control implementation/evidence trace
is in the [AU control narrative](../AU-controls.md). The implemented audit subsystem is in
[`internal/audit/`](../../../internal/audit/).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is **not
yet authorized** (**no ATO**) and not in production use. This policy documents the audit *discipline*
the program operates under and the controls that are *actually implemented* in code — it is not a
claim that every AU control is operating or has been assessed. Per-control status is tracked in the
[control matrix](../control-matrix.csv) and open weaknesses in the [POA&M](../POAM.md), with
remediation phases (P0–P12) defined in `../plans/remediation-roadmap.md`.

**Annual review.** This policy is reviewed and updated at least **annually**. The last review was
**2026-06-01**; the **next review is 2027-06-01**. It is also reviewed whenever a significant change
to the audit subsystem occurs — a new auditable event class, a change to the record schema
([`internal/audit/schema.json`](../../../internal/audit/schema.json)), the redaction rules, the
integrity/hash-chain mechanism, the retention floor, the forwarding path, or the cluster apiserver
audit policy. Reviews are recorded by updating the `last_reviewed`/`next_review` front-matter and the
version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that every security-relevant action in KP produces a
sufficiently attributed, time-stamped, tamper-evident, and retained audit record; that audit records
are protected from unauthorized modification and from loss on process failure; and that records can
be reduced and reviewed. It applies to:

- **Admission decisions** — every allow/deny rendered by the admission-webhook
  ([`internal/audit/logger.go`](../../../internal/audit/logger.go) `LogDecision`,
  [`internal/admission/controller.go`](../../../internal/admission/controller.go)).
- **Management-plane configuration changes** — policy/bundle/exception CRUD and compliance-report
  generation in the policy-manager
  ([`internal/policymanager/manager.go`](../../../internal/policymanager/manager.go)
  `LogConfigChange`), CRD reconcile and exception-expiry events
  ([`internal/policymanager/controller.go`](../../../internal/policymanager/controller.go)), and
  dashboard write attempts ([`cmd/dashboard/proxy.go`](../../../cmd/dashboard/proxy.go)
  `DashboardWriteAttempt`).
- **Cluster apiserver audit** — security-relevant Kubernetes API events captured by
  [`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../../deployments/kubernetes/cluster-audit/audit-policy.yaml).
- All personnel filling the System Owner, ISSO, Maintainer/CODEOWNERS, and operator roles.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see
[roles-raci.md](../roles-raci.md)). All `@kube-policies.io` contacts referenced in procedures are
**placeholders**.

## 2 AU-1 — Audit and Accountability Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this AU policy and the procedures needed to
implement it; shall designate an official to manage them; and shall review and update both on a
defined frequency. This document is that policy; the procedures are in
[../procedures/AU-procedures.md](../procedures/AU-procedures.md) and the technical
implementation/evidence trace in [../AU-controls.md](../AU-controls.md).

### 2.2 AU-1(a) — Scope and recipients

This policy applies to the organizational scope in §1. It is disseminated to the System Owner, ISSO,
AO, Maintainers, and all repository contributors by being maintained in version control under
[`docs/compliance/policies/`](.) and referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), AU
family) and the [CRM](../CRM.md).

### 2.3 AU-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update this
policy and its procedures, with the **System Owner (TBD — assign before assessment)** accountable
for adequacy and resourcing.

### 2.4 AU-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This AU policy (AU-1) | ISSO | At least annually (next: 2027-06-01) | New auditable event class; schema change; integrity/retention change; assessor finding |
| AU procedures ([AU-procedures.md](../procedures/AU-procedures.md)) | ISSO | At least annually (next: 2027-06-01) | Procedure drift; new emitted record/metric; forwarding-path change |
| AU control narrative ([AU-controls.md](../AU-controls.md)) | ISSO | Per audit-subsystem change + annually | New control mapping; test rename; residual closure |
| Cluster apiserver audit policy | Operator | Per cluster baseline change | New security-relevant resource; CIS benchmark update |

"Significant change" includes any change to the audit record schema, the redaction ruleset, the
HMAC hash-chain mechanism, the retention floor, the overflow policy, the off-host forwarding
configuration, or the set of audited management-plane events.

## 3 AU-2 — Event selection (auditable events)

KP shall, at minimum, generate an audit record for the following event classes:

1. **Every admission allow/deny decision** rendered by the webhook, including the requested object's
   GVK, namespace, name, the decision, and the matched policy/exception context
   ([`internal/audit/logger.go`](../../../internal/audit/logger.go) `LogDecision`).
2. **Every management-plane configuration mutation** — create/update/delete of policies, bundles,
   and exceptions; compliance-report generation; CRD reconcile (UPSERT/DELETE); and
   exception-expiry transitions
   ([`internal/policymanager/manager.go`](../../../internal/policymanager/manager.go) `LogConfigChange`,
   [`internal/policymanager/controller.go`](../../../internal/policymanager/controller.go)).
3. **Every dashboard write attempt** (mutating proxied request), recorded at the proxy boundary
   ([`cmd/dashboard/proxy.go`](../../../cmd/dashboard/proxy.go) `DashboardWriteAttempt`). Read-only
   RPCs (validate/evaluate/test) and GET/HEAD are **intentionally not audited** to control volume.
4. **Security-relevant cluster API events** captured by the apiserver audit policy
   ([`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../../deployments/kubernetes/cluster-audit/audit-policy.yaml)):
   secrets/configmaps/RBAC/webhook-configs/KP CRDs at RequestResponse level; workload mutations at
   Metadata level; high-volume read-only list/watch on non-security resources omitted. Operator
   guidance: [`docs/audit/cluster-audit-policy.md`](../../audit/cluster-audit-policy.md).

The selected event set shall be reviewed at least annually (AU-2 review obligation) and on any
change to the system's security-relevant surface.

## 4 AU-3 / AU-3(1) — Content of audit records and admission-decision records

Each KP audit record shall capture **who, what, when, where, and the outcome**. The `Event` schema
([`internal/audit/schema.json`](../../../internal/audit/schema.json), `schema_version` `1.0.0`)
requires, where applicable: the authenticated principal (subject/username), the requested resource,
the decision/outcome, dual UTC timestamps (§7), the `correlation_id` (§8), and the attribution fields
`source_ip`, `user_agent`, `request_uri`, `apiserver_id`, and `admission_webhook_config`
([`internal/audit/logger.go`](../../../internal/audit/logger.go)), populated by `newAuditContext`
([`internal/admission/controller.go`](../../../internal/admission/controller.go)).

**Peer-IP integrity (AU-3).** `source_ip` shall be derived from the trusted transport peer, not from
client-controlled headers: the admission-webhook gin router runs `SetTrustedProxies(nil)`
([`cmd/admission-webhook/main.go`](../../../cmd/admission-webhook/main.go)) so a spoofed
`X-Forwarded-For` cannot forge `source_ip`. **Residual:** `source_ip` is the apiserver/proxy peer,
**not** the originating end-user client; `apiserver_id`/`admission_webhook_config` are correlation
handles for the cluster apiserver audit, not webhook-asserted facts (POAM-013).

**Additional information and redaction (AU-3(1) / SI-12).** Every record carries `schema_version`.
Audited object payloads shall be **redacted before persistence**: Secret data and credential-like
keys are replaced with `[REDACTED]` by `MaybeRedact`
([`internal/audit/redaction.go`](../../../internal/audit/redaction.go)) **before** the record is
sealed or written. Redaction is fail-safe: a non-object/malformed payload is replaced wholesale
rather than risk leaking a secret.

## 5 AU-4 — Audit storage capacity, and AU-11 — retention

KP shall bound audit storage and retain records for the required period.

- **Capacity (AU-4).** The rotating `FileBackend`
  ([`internal/audit/logger.go`](../../../internal/audit/logger.go)) caps on-disk usage via
  `max_size_mb` (per-file size) and `max_backups` (file count) using lumberjack. Durable storage is
  provided by [`admission-webhook-audit-pvc.yaml`](../../../charts/kube-policies/templates/admission-webhook-audit-pvc.yaml).
- **Retention (AU-11).** `validateAudit`
  ([`internal/config/config.go`](../../../internal/config/config.go)) **rejects** any
  `audit.retention` below the FedRAMP-Moderate **90-day** floor; `ParseRetention` accepts a `d`
  (days) suffix and the value maps to lumberjack `MaxAge`. The cluster apiserver audit policy
  documents the matching `--audit-log-maxage=90`.
- **Residual.** The audit PVC is `ReadWriteOnce`; the webhook defaults to `replicaCount: 2`. RWO is
  single-node only — the **forwarder is the scalable durable path** (POAM-010, POAM-011).

## 6 AU-5 — Response to audit logging process failures

KP shall not silently lose audit records on backpressure or shutdown.

- **Overflow policy.** `overflow_policy` is operator-selectable
  ([`internal/audit/logger.go`](../../../internal/audit/logger.go)): `block` is **fail-closed**
  (applies backpressure so no record is silently dropped); `drop` (default) never blocks the hot path
  but increments a dropped-event metric so operators can **alert** on loss.
- **Graceful shutdown.** On SIGINT/SIGTERM, `Logger.Close()`
  ([`cmd/admission-webhook/main.go`](../../../cmd/admission-webhook/main.go)) drains the buffer and
  flushes pending records before exit.

Operators running at Moderate shall configure `overflow_policy: block` or alert on the drop metric;
the choice and its rationale shall be recorded per the procedures.

## 7 AU-8 — Time stamps

Every record shall carry trustworthy UTC time. KP records **dual UTC timestamps**:
`request_received_timestamp` (when the controller received the request) and `stage_timestamp` (when
the record was emitted), set in `LogDecision`
([`internal/audit/logger.go`](../../../internal/audit/logger.go)). Hosts are expected to be
NTP-synchronized; the apiserver and webhook clocks are the authoritative time sources for their
respective records. Time-source and NTP guidance is in
[`docs/audit/time-synchronization.md`](../../audit/time-synchronization.md).

## 8 AU-12 / AU-12(1) — Audit generation and time-correlated trail

- **Generation (AU-12).** KP generates records at every auditable point in §3: admission, management
  plane, dashboard, and the cluster apiserver policy.
- **Time-correlated trail (AU-12(1)).** Every record carries a `correlation_id`
  ([`internal/audit/logger.go`](../../../internal/audit/logger.go)); admission uses `req.UID`;
  `CorrelationMiddleware` ([`internal/policymanager/router.go`](../../../internal/policymanager/router.go))
  propagates `X-Correlation-Id` (fallback `X-Request-Id`) across the admission → policy-manager →
  dashboard chain, enabling a system-wide time-correlated trail. **Residual:** cross-repository
  correlation across KP records and the cluster apiserver audit is performed in the downstream SIEM
  (POAM-028).

## 9 AU-9 / AU-9(2) — Protection of audit information

KP shall protect audit records from unauthorized modification and shall support storing them on a
separate system.

- **Tamper-evidence (AU-9).** When integrity is enabled, each record is written as a sealed HMAC
  envelope `{"record":…,"hmac":…}` via `Chainer.Seal`; `VerifyChain` / `VerifyChainFiles`
  ([`internal/audit/integrity.go`](../../../internal/audit/integrity.go)) detect byte-flips, deleted
  or reordered records, and wrong-key tampering, **including across file rotation**. The HMAC key is
  delivered via [`audit-integrity-secret.yaml`](../../../charts/kube-policies/templates/audit-integrity-secret.yaml).
- **Off-host storage (AU-9(2)).** The in-process `ForwardBackend` (backend `"forward"`,
  [`internal/audit/forward_backend.go`](../../../internal/audit/forward_backend.go)) ships records
  off-host over **TLS** with a **disk spool** and **ordered replay** on reconnect; the DaemonSet
  shipper [`audit-forwarder-daemonset.yaml`](../../../charts/kube-policies/templates/audit-forwarder-daemonset.yaml)
  is the deployment path; operator guidance in
  [`docs/audit/forwarding.md`](../../audit/forwarding.md). **Residual:** both are **default-off** and
  **unit-tested only** — no live-cluster proof (POAM-012).

## 10 AU-6 / AU-7 — Review, analysis, reporting, and reduction

KP shall provide audit reduction and report generation, and shall support review.

- **Reduction / report (AU-7, AU-6).** `GenerateComplianceReport` / `ListComplianceFrameworks`
  ([`internal/policymanager/compliance.go`](../../../internal/policymanager/compliance.go)) read the
  local audit file **read-only** and produce filtered (time-range, namespace, decision) compliance
  reports, transparently unwrapping sealed envelopes.
- **Residual.** Reports read **only** the local file backend; rotated-out and forwarded records are
  out of scope, and automated analysis/correlation is the downstream SIEM's responsibility
  (POAM-012, POAM-038). The compliance read path is verified non-mutating.

## 11 Roles and responsibilities (summary)

| Role | Holder | AU responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for audit-program adequacy/resourcing; approves this policy. |
| ISSO | TBD — assign before assessment | Designated official managing this policy/procedures; defines the audited-event set; reviews audit records and integrity-verification results; maintains the POA&M for AU findings. |
| Maintainers / CODEOWNERS | TBD — assign | Review PRs that change the audit schema, redaction rules, integrity mechanism, or audited-event set; enforce that new mutating endpoints emit audit records. |
| Operator | TBD — assign | Configures retention (≥90d), `overflow_policy`, the integrity HMAC key, and the forwarder; performs periodic chain verification and log review. |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the SSP; renders the authorization decision. |

Contacts referenced operationally (e.g., `secops@kube-policies.io`, `isso@kube-policies.io`) are
**placeholders** pending role assignment.

## 12 Compliance, exceptions, and enforcement

- A new mutating management-plane or dashboard endpoint that does not emit an audit record is a
  finding requiring remediation before merge (enforced by review per §11 and the
  `*_audit_test.go` suites).
- Configuring `audit.retention` below 90 days is rejected at startup by `validateAudit`; bypassing
  this requires ISSO and System Owner approval and a corresponding POA&M entry.
- Running at Moderate with `overflow_policy: drop` and no alert on the drop metric is a documented
  deviation requiring ISSO acknowledgement.
- Disabling audit integrity (the HMAC hash-chain) in an assessed environment requires ISSO approval
  and a POA&M entry.

## 13 References

- AU procedures: [../procedures/AU-procedures.md](../procedures/AU-procedures.md)
- AU control narrative: [../AU-controls.md](../AU-controls.md)
- Audit subsystem: [`internal/audit/logger.go`](../../../internal/audit/logger.go) · [`internal/audit/schema.json`](../../../internal/audit/schema.json) · [`internal/audit/integrity.go`](../../../internal/audit/integrity.go) · [`internal/audit/redaction.go`](../../../internal/audit/redaction.go) · [`internal/audit/forward_backend.go`](../../../internal/audit/forward_backend.go)
- Retention validation: [`internal/config/config.go`](../../../internal/config/config.go)
- Cluster audit policy: [`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../../deployments/kubernetes/cluster-audit/audit-policy.yaml)
- Operator docs: [`docs/audit/time-synchronization.md`](../../audit/time-synchronization.md) · [`docs/audit/forwarding.md`](../../audit/forwarding.md) · [`docs/audit/cluster-audit-policy.md`](../../audit/cluster-audit-policy.md)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (AU-1 family + SI-12); FedRAMP Moderate baseline; CIS Kubernetes Benchmark §3.2; FIPS-199.
