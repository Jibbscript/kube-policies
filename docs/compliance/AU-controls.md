---
title: "Audit & Accountability Control Narrative — Kube-Policies (KP)"
control_family: "AU — Audit and Accountability"
controls: "AU-2, AU-3, AU-3(1), AU-4, AU-5, AU-6, AU-6(3), AU-7, AU-8, AU-9, AU-9(2), AU-11, AU-12, AU-12(1), SI-12"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Audit & Accountability Control Narrative — Kube-Policies (KP)

This document is the SSP-style control narrative for the Audit and Accountability (AU) family
(work unit **AUD-WU-21**, NIST **CA-2** / FedRAMP SSP). It maps **each in-scope AU control** to the
concrete implementation artifact (Go source, manifest, or schema) **and** to the acceptance test
that evidences it, so a reviewer can trace every control to code that exists in this repository.

Kube-Policies is a **pre-1.0 Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. This narrative claims only that
controls are **implemented** with **evidence available** (source + passing unit tests on the working
branch). It does **not** claim any control is "operating", "assessed", or "demonstrated in a live
cluster". Residuals and known limitations are stated explicitly in §3 and cross-referenced to the
[POA&M](POAM.md).

**Policy and procedures.** The governing AU policy is at
[policies/AU-policy.md](policies/AU-policy.md); operational procedures are at
[procedures/AU-procedures.md](procedures/AU-procedures.md).

---

## 1 Audit subsystem facts

| Fact | Value |
|---|---|
| In-process audit logger | [`internal/audit/logger.go`](../../internal/audit/logger.go) |
| Audit record schema | [`internal/audit/schema.json`](../../internal/audit/schema.json); `schema_version` = `1.0.0` (`AuditSchemaVersion`) |
| Decision attribution wiring | [`internal/admission/controller.go`](../../internal/admission/controller.go) `newAuditContext` |
| Trusted-proxy hardening | `router.SetTrustedProxies(nil)` in [`cmd/admission-webhook/main.go`](../../cmd/admission-webhook/main.go) |
| Redaction (PII/Secret) | [`internal/audit/redaction.go`](../../internal/audit/redaction.go) |
| Tamper-evidence (hash-chain) | [`internal/audit/integrity.go`](../../internal/audit/integrity.go) (`Chainer.Seal` / `VerifyChain` / `VerifyChainFiles`) |
| Rotating file backend | `FileBackend` in [`internal/audit/logger.go`](../../internal/audit/logger.go) (lumberjack: `max_size_mb`, `max_backups`) |
| Retention validation | `ParseRetention` / `validateAudit` in [`internal/config/config.go`](../../internal/config/config.go) (90d floor) |
| Off-host forwarding (in-process) | `ForwardBackend` (TLS + disk-spool + replay) in [`internal/audit/forward_backend.go`](../../internal/audit/forward_backend.go); backend `"forward"` |
| Off-host forwarding (DaemonSet) | [`charts/kube-policies/templates/audit-forwarder-daemonset.yaml`](../../charts/kube-policies/templates/audit-forwarder-daemonset.yaml) (default-off) |
| Management-plane config audit | `LogConfigChange` in [`internal/policymanager/manager.go`](../../internal/policymanager/manager.go) + reconcilers in [`internal/policymanager/controller.go`](../../internal/policymanager/controller.go) |
| Dashboard write audit | `DashboardWriteAttempt` in [`cmd/dashboard/proxy.go`](../../cmd/dashboard/proxy.go) |
| Correlation propagation | `CorrelationMiddleware` in [`internal/policymanager/router.go`](../../internal/policymanager/router.go); `correlation_id` field in `logger.go` |
| Audit reduction / report | `GenerateComplianceReport` / `ListComplianceFrameworks` in [`internal/policymanager/compliance.go`](../../internal/policymanager/compliance.go) (read-only) |
| Cluster apiserver audit policy | [`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../deployments/kubernetes/cluster-audit/audit-policy.yaml) |
| Operator docs | Timestamps: [`docs/audit/time-synchronization.md`](../audit/time-synchronization.md) · Forwarding: [`docs/audit/forwarding.md`](../audit/forwarding.md) · Cluster policy: [`docs/audit/cluster-audit-policy.md`](../audit/cluster-audit-policy.md) |

---

## 2 Control-to-evidence trace matrix

Each row maps one AU control to the **artifact** that implements it and the **acceptance test** that
evidences it. Test names are exact and resolve in the cited file.

| Control | Title | Implementation status | Implementation artifact (path) | Acceptance test (file :: TestName) |
|---|---|---|---|---|
| **AU-2** | Event Logging | **Implemented** | Admission allow/deny: `LogDecision` in [`internal/audit/logger.go`](../../internal/audit/logger.go). Mgmt-plane events: 9× `LogConfigChange` in [`internal/policymanager/manager.go`](../../internal/policymanager/manager.go); reconcile + exception-expiry in [`internal/policymanager/controller.go`](../../internal/policymanager/controller.go) (`auditReconcile`, `auditExpiry`→`LogSystemEvent "ExceptionExpired"`); dashboard writes in [`cmd/dashboard/proxy.go`](../../cmd/dashboard/proxy.go). Cluster events: [`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../deployments/kubernetes/cluster-audit/audit-policy.yaml). | `internal/policymanager/manager_audit_test.go :: TestManagerAudit_AttributesAuthenticatedPrincipal`; `cmd/dashboard/proxy_audit_test.go :: TestProxyAudit_MutatingRequest_AllowWritesTrue` |
| **AU-3** | Content of Audit Records | **Implemented** | Attribution fields `source_ip`, `user_agent`, `request_uri`, `apiserver_id`, `admission_webhook_config` on `Event` in [`internal/audit/logger.go`](../../internal/audit/logger.go); populated by `newAuditContext` in [`internal/admission/controller.go`](../../internal/admission/controller.go); peer-IP integrity via `SetTrustedProxies(nil)` in [`cmd/admission-webhook/main.go`](../../cmd/admission-webhook/main.go). | `internal/admission/audit_context_test.go`; `internal/audit/logger_p7_test.go :: TestLogDecision_AttributionTimestampsCorrelation` |
| **AU-3(1)** | Content of Audit Records \| Additional Audit Information | **Implemented** | Versioned schema + redaction: `schema_version` (`AuditSchemaVersion`) on `Event`, [`internal/audit/schema.json`](../../internal/audit/schema.json), and `MaybeRedact` in [`internal/audit/redaction.go`](../../internal/audit/redaction.go) (Secret data + credential-like keys → `[REDACTED]` before seal). | `internal/audit/redaction_test.go :: TestMaybeRedact_SecretData`; `internal/audit/redaction_test.go :: TestFileBackend_RedactionBeforeSeal` |
| **AU-4** | Audit Log Storage Capacity | **Implemented** | `FileBackend` (lumberjack) in [`internal/audit/logger.go`](../../internal/audit/logger.go) bounds on-disk size via `max_size_mb` + `max_backups`; durable PVC [`charts/kube-policies/templates/admission-webhook-audit-pvc.yaml`](../../charts/kube-policies/templates/admission-webhook-audit-pvc.yaml). | `internal/audit/rotation_test.go :: TestFileBackend_RotationPreservesChain`; `internal/audit/rotation_test.go :: TestFileBackend_RetentionMapsToMaxAge` |
| **AU-5** | Response to Audit Logging Process Failures | **Implemented** | `overflow_policy` `drop`\|`block` in `LogDecision` write path ([`internal/audit/logger.go`](../../internal/audit/logger.go)): `block` is fail-closed (no silent loss); `drop` increments a dropped-event metric for alerting. SIGTERM flush via `Logger.Close()` in [`cmd/admission-webhook/main.go`](../../cmd/admission-webhook/main.go). | `internal/audit/logger_p7_test.go :: TestOverflowBlock_NoLoss`; `internal/audit/logger_p7_test.go :: TestGracefulClose_FlushesBuffer` |
| **AU-6** | Audit Record Review, Analysis, and Reporting | **Implemented (review tooling) / Partial (analysis)** | Read-only report generation over the local audit file: `GenerateComplianceReport` / `ListComplianceFrameworks` in [`internal/policymanager/compliance.go`](../../internal/policymanager/compliance.go). Off-host review path: `ForwardBackend` in [`internal/audit/forward_backend.go`](../../internal/audit/forward_backend.go) + [`charts/kube-policies/templates/audit-forwarder-daemonset.yaml`](../../charts/kube-policies/templates/audit-forwarder-daemonset.yaml). | `internal/policymanager/compliance_test.go :: TestCompliance_GenerateReport_Populated`; `internal/audit/forward_backend_test.go :: TestForwardBackend_DeliversOverTLS` |
| **AU-6(3)** | Audit Record Review \| Correlate Audit Record Repositories | **Implemented (mechanism) / Partial** | Cross-repository correlation is enabled by the shared `correlation_id` propagated by `CorrelationMiddleware` ([`internal/policymanager/router.go`](../../internal/policymanager/router.go)) and the off-host forward path ([`internal/audit/forward_backend.go`](../../internal/audit/forward_backend.go)) that ships KP records into the same SIEM as the cluster apiserver audit ([`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../deployments/kubernetes/cluster-audit/audit-policy.yaml)). Cross-repo correlation itself is performed in the downstream SIEM (out of KP scope). | `internal/audit/logger_p7_test.go :: TestLogDecision_AttributionTimestampsCorrelation`; `internal/audit/forward_backend_test.go :: TestForwardBackend_SpoolsAndReplays` |
| **AU-7** | Audit Reduction and Report Generation | **Implemented** | Filterable, read-only reduction over the local file backend (time-range, namespace, decision filters; sealed-envelope unwrap) in [`internal/policymanager/compliance.go`](../../internal/policymanager/compliance.go). | `internal/policymanager/compliance_test.go :: TestCompliance_TimeRangeFilter`; `internal/policymanager/compliance_test.go :: TestCompliance_NamespaceAndDecisionFilters` |
| **AU-8** | Time Stamps | **Implemented** | Dual UTC timestamps `request_received_timestamp` (controller entry) + `stage_timestamp` (record emit) on `Event`/`Context`, set in `LogDecision` ([`internal/audit/logger.go`](../../internal/audit/logger.go)); time-source/NTP guidance in [`docs/audit/time-synchronization.md`](../audit/time-synchronization.md). | `internal/audit/logger_p7_test.go :: TestLogDecision_AttributionTimestampsCorrelation`; `internal/audit/logger_p7_test.go :: TestLogDecision_TimestampCorrelationFallbacks` |
| **AU-9** | Protection of Audit Information | **Implemented** | Tamper-evident HMAC hash-chain: `Chainer.Seal` writes a sealed envelope `{"record":…,"hmac":…}` per line; `VerifyChain` / `VerifyChainFiles` detect byte-flips, deletions, reordering, and wrong-key tampering across rotation ([`internal/audit/integrity.go`](../../internal/audit/integrity.go)). HMAC key in [`charts/kube-policies/templates/audit-integrity-secret.yaml`](../../charts/kube-policies/templates/audit-integrity-secret.yaml). | `internal/audit/integrity_test.go :: TestVerifyChain_DetectsByteFlip`; `internal/audit/integrity_test.go :: TestVerifyChain_DetectsDeletedRecord`; `internal/audit/rotation_test.go :: TestFileBackend_RotationPreservesChain` |
| **AU-9(2)** | Protection of Audit Information \| Store on Separate Physical Systems | **Implemented (default-off) / Partial** | `ForwardBackend` (backend `"forward"`) ships records off-host over TLS with a disk spool + ordered replay on reconnect ([`internal/audit/forward_backend.go`](../../internal/audit/forward_backend.go)); DaemonSet shipper [`charts/kube-policies/templates/audit-forwarder-daemonset.yaml`](../../charts/kube-policies/templates/audit-forwarder-daemonset.yaml) (`audit.forwarder.enabled`, default `false`); operator guide [`docs/audit/forwarding.md`](../audit/forwarding.md). | `internal/audit/forward_backend_test.go :: TestForwardBackend_DeliversOverTLS`; `internal/audit/forward_backend_test.go :: TestForwardBackend_SpoolsAndReplays` |
| **AU-11** | Audit Record Retention | **Implemented** | `validateAudit` rejects `audit.retention` below the FedRAMP-Moderate 90-day floor; `ParseRetention` accepts a `d` (days) suffix and maps to lumberjack `MaxAge` ([`internal/config/config.go`](../../internal/config/config.go), [`internal/audit/logger.go`](../../internal/audit/logger.go)). | `internal/config/retention_test.go :: TestValidateAudit_RetentionFloor`; `internal/config/retention_test.go :: TestParseRetention`; `internal/audit/rotation_test.go :: TestFileBackend_RetentionMapsToMaxAge` |
| **AU-12** | Audit Record Generation | **Implemented** | KP generates records at every auditable point: admission (`LogDecision`), management plane (`LogConfigChange` ×9 + reconcile/expiry in [`internal/policymanager/controller.go`](../../internal/policymanager/controller.go)), dashboard (`DashboardWriteAttempt`), and the cluster apiserver policy ([`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../deployments/kubernetes/cluster-audit/audit-policy.yaml); operator guide [`docs/audit/cluster-audit-policy.md`](../audit/cluster-audit-policy.md)). | `internal/policymanager/manager_audit_test.go :: TestManagerAudit_UIDIsSubjectNotUsername`; `internal/policymanager/manager_audit_test.go :: TestManagerAudit_PlaygroundRPCsEmitNoConfigChange` |
| **AU-12(1)** | Audit Record Generation \| System-Wide / Time-Correlated Audit Trail | **Implemented (mechanism)** | `correlation_id` stamped on every record (`LogDecision`/`LogConfigChange`/`LogSystemEvent` in [`internal/audit/logger.go`](../../internal/audit/logger.go)); admission uses `req.UID`; `CorrelationMiddleware` propagates `X-Correlation-Id`/`X-Request-Id` across the admission → policy-manager → dashboard chain ([`internal/policymanager/router.go`](../../internal/policymanager/router.go)). | `internal/audit/logger_p7_test.go :: TestConfigAndSystemEvents_CorrelationSchema`; `internal/audit/logger_p7_test.go :: TestLogDecision_AttributionTimestampsCorrelation` |
| **SI-12** | Information Management and Retention | **Implemented** | Privacy-aware retention of audit information: redaction of Secret data + credential-like keys before persistence ([`internal/audit/redaction.go`](../../internal/audit/redaction.go), schema note in [`internal/audit/schema.json`](../../internal/audit/schema.json)); retention floor enforced in [`internal/config/config.go`](../../internal/config/config.go). | `internal/audit/redaction_test.go :: TestMaybeRedact_SensitiveKeys`; `internal/audit/redaction_test.go :: TestMaybeRedact_NonObjectFailSafe` |

---

## 3 Honest residuals (read before relying on any row above)

These are known limitations of the **implemented** controls. None is a claim of "operating" or
"assessed". Each maps to a POA&M entry where applicable.

1. **`source_ip` is the peer, not the originating client.** The `source_ip` recorded by
   `newAuditContext` is the apiserver/proxy peer address of the TLS connection terminating at the
   webhook, hardened against spoofed `X-Forwarded-For` by `SetTrustedProxies(nil)`. It is **not** the
   originating end-user client IP. End-user attribution comes from correlating with the cluster
   apiserver audit (AU-3 / POAM-013).
2. **`apiserver_id` / `admission_webhook_config` are correlation handles, not webhook-asserted
   facts.** These fields exist on the record to enable correlation with the cluster apiserver audit
   log; they are populated by correlation with that external source, not independently asserted by
   the webhook. (AU-3 / POAM-013.)
3. **Compliance reports read ONLY the local file backend.** `GenerateComplianceReport`
   ([`internal/policymanager/compliance.go`](../../internal/policymanager/compliance.go)) reads a
   single local audit file (read-only; verified non-mutating by
   `compliance_test.go :: TestCompliance_DoesNotMutateSourceFile`). Records that have rotated out or
   been forwarded off-host are **out of scope** of the report. Authoritative long-term review is the
   SIEM's job, not KP's. (AU-6 / AU-7 / POAM-012, POAM-038.)
4. **Off-host forwarding is default-off and unit-tested only.** Both the in-process `ForwardBackend`
   and the [`audit-forwarder-daemonset.yaml`](../../charts/kube-policies/templates/audit-forwarder-daemonset.yaml)
   are disabled by default and have **no live-cluster proof** — evidence is unit tests over a TLS
   loopback, not a deployed SIEM pipeline. (AU-6 / AU-9(2) / POAM-012.)
5. **The audit PVC is RWO and unsound for multi-replica.**
   [`admission-webhook-audit-pvc.yaml`](../../charts/kube-policies/templates/admission-webhook-audit-pvc.yaml)
   is `ReadWriteOnce`; the admission-webhook defaults to `replicaCount: 2`. A single RWO PVC cannot
   back multiple replicas safely. The **forwarder is the scalable durable path**; the PVC is for
   single-node use only. (AU-4 / AU-9 / POAM-010, POAM-011.)
6. **AU-6 analysis and AU-6(3) cross-repository correlation are downstream.** KP supplies the
   mechanism (`correlation_id`, off-host forwarding, read-only reduction) but the actual correlation
   and automated analysis are performed in the downstream SIEM (out of KP's control boundary). These
   rows are marked Partial accordingly. (POAM-012, POAM-028.)
7. **Pre-1.0 PoC, no ATO, no live CI.** All evidence is source + passing unit tests on branch
   `feat/p0-compliance-foundation`. No control is claimed to be operating in production.

POA&M cross-reference: [POAM-010](POAM.md) (AU-9 tamper-evidence / emptyDir),
[POAM-011](POAM.md) (AU-4 retention/capacity), [POAM-012](POAM.md) (AU-6 SIEM forwarding),
[POAM-013](POAM.md) (AU-3 attribution completeness), [POAM-028](POAM.md) (AU-12 time-correlated
trail), [POAM-038](POAM.md) (AU-7 reduction/report).

---

## 4 References

- AU policy: [policies/AU-policy.md](policies/AU-policy.md)
- AU procedures: [procedures/AU-procedures.md](procedures/AU-procedures.md)
- Audit logger + schema: [`internal/audit/logger.go`](../../internal/audit/logger.go) · [`internal/audit/schema.json`](../../internal/audit/schema.json)
- Integrity / redaction: [`internal/audit/integrity.go`](../../internal/audit/integrity.go) · [`internal/audit/redaction.go`](../../internal/audit/redaction.go)
- Forwarding: [`internal/audit/forward_backend.go`](../../internal/audit/forward_backend.go) · [`charts/kube-policies/templates/audit-forwarder-daemonset.yaml`](../../charts/kube-policies/templates/audit-forwarder-daemonset.yaml)
- Cluster audit policy: [`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../deployments/kubernetes/cluster-audit/audit-policy.yaml)
- Operator docs: [`docs/audit/time-synchronization.md`](../audit/time-synchronization.md) · [`docs/audit/forwarding.md`](../audit/forwarding.md) · [`docs/audit/cluster-audit-policy.md`](../audit/cluster-audit-policy.md)
- POA&M: [POAM.md](POAM.md) · Control matrix: [control-matrix.csv](control-matrix.csv) · Compliance index: [README.md](README.md)
- NIST SP 800-53 Rev 5 (AU-2, AU-3, AU-3(1), AU-4, AU-5, AU-6, AU-6(3), AU-7, AU-8, AU-9, AU-9(2), AU-11, AU-12, AU-12(1), SI-12); FedRAMP Moderate baseline; CIS Kubernetes Benchmark §3.2.
