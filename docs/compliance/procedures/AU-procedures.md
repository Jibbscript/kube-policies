---
title: "Audit and Accountability Procedures (AU) — Kube-Policies (KP)"
control_family: "AU — Audit and Accountability"
controls: "AU-1, AU-2, AU-3, AU-3(1), AU-4, AU-5, AU-6, AU-7, AU-8, AU-9, AU-9(2), AU-11, AU-12, AU-12(1), SI-12"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Audit and Accountability Procedures — Kube-Policies (KP)

These are the operational procedures that implement the Audit and Accountability policy
([../policies/AU-policy.md](../policies/AU-policy.md)) for the Kube-Policies system (KP). They map
each auditable event class to the **actual emitted record or metric**, and cover how audit records
are attributed, protected (integrity + redaction), retained, forwarded off-host, and reviewed.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is **not yet
authorized** (**no ATO**). These procedures describe what is *actually implemented* in the shipped
code and what an operator or assessor can run to verify it. Where a control is Partial or has a
residual, the procedure says so; open weaknesses are tracked in [../POAM.md](../POAM.md) and the
phased plan `../plans/remediation-roadmap.md`. All `@kube-policies.io` contacts below
are **placeholders** pending role assignment.

**Annual review.** These procedures are reviewed and updated at least **annually** (last review
**2026-06-01**; next review **2027-06-01**) and on any significant change to the audit subsystem
(record schema, redaction rules, integrity mechanism, retention floor, overflow policy, forwarding
path, or the cluster apiserver audit policy). Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version.

## 1 Scope

These procedures apply to the auditable events and components in
[AU-policy.md §1](../policies/AU-policy.md#1-purpose-and-applicability): admission decisions,
management-plane configuration changes, dashboard write attempts, and the cluster apiserver audit.
The implementation/evidence trace for each control is in [../AU-controls.md](../AU-controls.md).

## 2 Auditable-event → emitted-record map (AU-2 / AU-3 / AU-12)

Each KP auditable event maps to a concrete emitted record. Records are written by the in-process
logger ([`internal/audit/logger.go`](../../../internal/audit/logger.go)) to the configured backend
(file / forward / discard).

| Auditable event | Emitter (path) | Emitted record / event type | Key recorded fields |
|---|---|---|---|
| Admission allow/deny | `LogDecision` ([`internal/audit/logger.go`](../../../internal/audit/logger.go)); ctx built by `newAuditContext` ([`internal/admission/controller.go`](../../../internal/admission/controller.go)) | Decision record | decision, GVK/namespace/name, principal, `source_ip`, `user_agent`, `request_uri`, `apiserver_id`, `admission_webhook_config`, dual timestamps, `correlation_id`, `schema_version` |
| Policy create/update/delete | `LogConfigChange` ([`internal/policymanager/manager.go`](../../../internal/policymanager/manager.go)) | ConfigurationChange (`CREATE`/`UPDATE`/`DELETE`, resource `policy`) | principal, resourceID, change set, `correlation_id` |
| Bundle create | `LogConfigChange` ([`internal/policymanager/manager.go`](../../../internal/policymanager/manager.go)) | ConfigurationChange (`CREATE`, resource `bundle`) | principal, bundleID, change set |
| Exception create/update/delete | `LogConfigChange` ([`internal/policymanager/manager.go`](../../../internal/policymanager/manager.go)) | ConfigurationChange (resource `exception`) | principal, exceptionID, change set |
| Compliance-report generation | `LogConfigChange` ([`internal/policymanager/manager.go`](../../../internal/policymanager/manager.go)) | ConfigurationChange (`GENERATE`, resource `compliance_report`) | principal, reportID |
| CRD reconcile (policy / exception) | `auditReconcile`→`LogConfigChange` ([`internal/policymanager/controller.go`](../../../internal/policymanager/controller.go)) | ConfigurationChange (`UPSERT`/`DELETE`) attributed to the synthesized controller identity | resource, id, change set |
| Exception expiry (CRD reconciler) | `auditExpiry`→`LogSystemEvent` ([`internal/policymanager/controller.go`](../../../internal/policymanager/controller.go)) | SystemEvent `ExceptionExpired` | exception id/ns/name/uid, generation, policyID |
| Exception expiry (in-memory ticker) | `checkExpiredExceptions` ([`internal/policymanager/manager.go`](../../../internal/policymanager/manager.go)) | lifecycle audit event (first transition into `expired` only) | exception id |
| Dashboard write attempt | `DashboardWriteAttempt`→`LogSystemEvent` ([`cmd/dashboard/proxy.go`](../../../cmd/dashboard/proxy.go)) | SystemEvent `DashboardWriteAttempt` (mutating requests only) | principal, method, path, allow-writes flag |
| Cluster API security event | apiserver audit ([`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../../deployments/kubernetes/cluster-audit/audit-policy.yaml); guide [`docs/audit/cluster-audit-policy.md`](../../audit/cluster-audit-policy.md)) | k8s `audit.k8s.io/v1` event | RequestResponse for secrets/RBAC/CRDs; Metadata for workloads |

**Verification (events emit as documented):**

```console
go test ./internal/audit/... ./internal/policymanager/... ./internal/admission/... ./cmd/dashboard/...
```

Targeted evidence: `manager_audit_test.go::TestManagerAudit_AttributesAuthenticatedPrincipal`,
`manager_audit_test.go::TestManagerAudit_PlaygroundRPCsEmitNoConfigChange` (read-only RPCs emit
nothing), `proxy_audit_test.go::TestProxyAudit_ReadOnlyRPC_NoRecord` and
`::TestProxyAudit_GET_NoRecord` (reads not audited), `audit_context_test.go` (attribution fields
populated).

## 3 Record content and attribution (AU-3 / AU-3(1))

### 3.1 What each record must contain

The authoritative shape is [`internal/audit/schema.json`](../../../internal/audit/schema.json)
(`schema_version` `1.0.0`). Validate a captured record against it:

```console
# Example: validate emitted records against the published schema (requires a JSON-schema validator)
jq -c '.record // .' audit.log | while read -r line; do
  printf '%s' "$line" | <your-jsonschema-validator> internal/audit/schema.json
done
```

### 3.2 Trusting `source_ip`

`source_ip` is the trusted transport peer. The admission-webhook gin router is configured with
`SetTrustedProxies(nil)` ([`cmd/admission-webhook/main.go`](../../../cmd/admission-webhook/main.go))
so a forged `X-Forwarded-For` cannot spoof it. **Operator note (residual):** `source_ip` is the
apiserver/proxy peer, **not** the originating end-user client; `apiserver_id` and
`admission_webhook_config` are handles for correlating with the cluster apiserver audit, not
facts asserted by the webhook (POAM-013). End-user attribution requires joining KP records to the
apiserver audit on `correlation_id`/UID downstream.

### 3.3 Redaction (AU-3(1) / SI-12)

Secret data and credential-like keys in audited object payloads are replaced with `[REDACTED]` by
`MaybeRedact` ([`internal/audit/redaction.go`](../../../internal/audit/redaction.go)) **before** the
record is sealed or written to disk. Confirm:

```console
go test ./internal/audit/ -run 'TestMaybeRedact_SecretData|TestFileBackend_RedactionBeforeSeal|TestMaybeRedact_SensitiveKeys'
```

Operators must keep `audit.redact_objects` enabled (default) in any environment handling real
Secrets.

## 4 Timestamps (AU-8)

Each record carries dual UTC timestamps: `request_received_timestamp` (controller entry) and
`stage_timestamp` (record emit), set in `LogDecision`
([`internal/audit/logger.go`](../../../internal/audit/logger.go)).

```console
go test ./internal/audit/ -run 'TestLogDecision_AttributionTimestampsCorrelation|TestLogDecision_TimestampCorrelationFallbacks'
```

**Operator prerequisite:** all nodes running the webhook, policy-manager, and apiserver must be
NTP-synchronized so the two clocks (apiserver audit and KP records) align for correlation. See
[`docs/audit/time-synchronization.md`](../../audit/time-synchronization.md) for the time-source and
NTP guidance.

## 5 Storage capacity and retention (AU-4 / AU-11)

### 5.1 Configure retention (≥90 days)

`audit.retention` is validated at startup by `validateAudit`
([`internal/config/config.go`](../../../internal/config/config.go)) and **rejected** if below the
90-day FedRAMP-Moderate floor. Use a `d` suffix for days:

```yaml
audit:
  enabled: true
  retention: "90d"        # rejected if < 90d
  max_size_mb: 100        # per-file cap (lumberjack)
  max_backups: 10         # rotated-file count cap
```

Verify the floor and rotation mapping:

```console
go test ./internal/config/ -run 'TestValidateAudit_RetentionFloor|TestParseRetention'
go test ./internal/audit/  -run 'TestFileBackend_RetentionMapsToMaxAge|TestFileBackend_RotationPreservesChain'
```

### 5.2 Durable storage and the multi-replica residual

Durable on-disk storage is provided by
[`admission-webhook-audit-pvc.yaml`](../../../charts/kube-policies/templates/admission-webhook-audit-pvc.yaml).
**The PVC is `ReadWriteOnce` and the webhook defaults to `replicaCount: 2`** — a single RWO PVC
cannot back multiple replicas. For multi-replica deployments, do **not** rely on the PVC for the
audit-of-record; enable the **forwarder** (§7) as the scalable durable path, or set
`admissionWebhook.replicaCount: 1` (POAM-010, POAM-011).

## 6 Audit-failure handling (AU-5)

### 6.1 Choose an overflow policy

```yaml
audit:
  overflow_policy: "block"   # fail-closed: no silent loss (recommended for Moderate)
  # overflow_policy: "drop"  # default: never blocks the hot path; emits a dropped-event metric
```

`block` applies backpressure so no record is silently lost; `drop` increments a dropped-event metric
([`internal/audit/logger.go`](../../../internal/audit/logger.go)). If you run `drop`, you **must**
alert on the drop metric.

```console
go test ./internal/audit/ -run 'TestOverflowBlock_NoLoss|TestGracefulClose_FlushesBuffer'
```

### 6.2 Graceful shutdown

On SIGINT/SIGTERM the process calls `Logger.Close()`
([`cmd/admission-webhook/main.go`](../../../cmd/admission-webhook/main.go)), draining and flushing
the buffer so in-flight records are persisted, not lost. No operator action is required beyond using
ordinary `SIGTERM` (the Kubernetes default) for pod termination.

## 7 Off-host forwarding (AU-9(2) / AU-6)

Operator guide for both paths: [`docs/audit/forwarding.md`](../../audit/forwarding.md).

### 7.1 In-process forward backend

Set the backend to `"forward"` to ship records off-host over TLS with a local disk spool and ordered
replay on reconnect ([`internal/audit/forward_backend.go`](../../../internal/audit/forward_backend.go)):

```yaml
audit:
  backend: "forward"
  config:
    forward_address: "siem.example.internal:6514"   # TLS receiver (required)
    # forward_spool_dir defaults to <log dir>/spool
    # forward_ca_file / forward_server_name / forward_tls_insecure / forward_dial_timeout optional
```

The `forward_*` keys live under `audit.config` (a free-form string map), matching
how `forward_backend.go` reads them (`cfg.Config["forward_address"]`).

The spool is the local-durability guarantee: if the receiver is unreachable, records are spooled to
disk and replayed in order when the connection recovers.

```console
go test ./internal/audit/ -run 'TestForwardBackend_DeliversOverTLS|TestForwardBackend_SpoolsAndReplays'
```

### 7.2 DaemonSet shipper (deployment path)

The chart ships a node-level forwarder
([`audit-forwarder-daemonset.yaml`](../../../charts/kube-policies/templates/audit-forwarder-daemonset.yaml)),
**default-off**:

```yaml
audit:
  forwarder:
    enabled: true          # default false
    destination:
      # one of: loki / elasticsearch / splunk / syslog (TLS toggles per destination)
```

**Residual:** both forwarding paths are **default-off** and **unit-tested only** — there is **no
live-cluster proof** of end-to-end delivery to a real SIEM (POAM-012). Enabling and validating
forwarding against a live receiver is a pre-assessment task.

## 8 Audit-information protection — integrity verification (AU-9)

### 8.1 Enable the hash-chain

Provide the HMAC key via
[`audit-integrity-secret.yaml`](../../../charts/kube-policies/templates/audit-integrity-secret.yaml).
When enabled, each line on disk is a sealed envelope `{"record": <event>, "hmac": <hex>}`
([`internal/audit/integrity.go`](../../../internal/audit/integrity.go) `Chainer.Seal`).

### 8.2 Verify the chain (periodic + on suspicion of tampering)

`VerifyChainFiles` validates the chain across the live file and its rotated backups; any byte-flip,
deleted/reordered record, or wrong key fails verification.

```console
# Unit-level proof of the detection guarantees:
go test ./internal/audit/ -run 'TestVerifyChain_Untampered|TestVerifyChain_DetectsByteFlip|TestVerifyChain_DetectsDeletedRecord|TestVerifyChain_WrongKey|TestFileBackend_RotationPreservesChain'
```

Run chain verification on the operator's schedule (see §11) and immediately on any indication of log
tampering. A verification failure is a security incident: preserve the files and notify the ISSO
(`isso@kube-policies.io`, placeholder).

## 9 Time-correlated trail (AU-12(1))

Every record carries `correlation_id`; the admission path uses `req.UID`. `CorrelationMiddleware`
([`internal/policymanager/router.go`](../../../internal/policymanager/router.go)) reads inbound
`X-Correlation-Id` (fallback `X-Request-Id`), stashes it, and echoes it back, so a single id flows
across admission → policy-manager → dashboard. To trace one logical action end-to-end, filter all
records by its `correlation_id`.

```console
go test ./internal/audit/ -run 'TestConfigAndSystemEvents_CorrelationSchema|TestLogDecision_AttributionTimestampsCorrelation'
```

**Residual:** correlating KP records with the cluster apiserver audit is done downstream in the SIEM
(POAM-028).

## 10 Audit reduction and review (AU-6 / AU-7)

### 10.1 Generate a reduced compliance report

`GenerateComplianceReport` / `ListComplianceFrameworks`
([`internal/policymanager/compliance.go`](../../../internal/policymanager/compliance.go)) read the
local audit file **read-only** and produce a filtered report (time-range, namespace, decision),
unwrapping sealed envelopes transparently. The read path is verified non-mutating.

```console
go test ./internal/policymanager/ -run 'TestCompliance_GenerateReport_Populated|TestCompliance_TimeRangeFilter|TestCompliance_NamespaceAndDecisionFilters|TestCompliance_SealedEnvelopeUnwrapped|TestCompliance_DoesNotMutateSourceFile'
```

### 10.2 Review cadence and residual

The ISSO reviews audit records and report output on the schedule in §11. **Residual:** the report
reads **only** the local file backend — records that have rotated out or been forwarded off-host are
out of scope, and automated analysis/correlation is the downstream SIEM's responsibility (POAM-012,
POAM-038). For full-coverage review, query the SIEM that receives the forwarded stream (§7).

## 11 Cadence summary

| Activity | Frequency | Owner |
|---|---|---|
| Verify the audit hash-chain (`VerifyChainFiles`) | Weekly + on suspicion of tampering | Operator |
| Review admission deny records + dashboard write attempts | Weekly | ISSO |
| Generate + review compliance report | Monthly | ISSO |
| Confirm retention ≥ 90d and rotation healthy | Monthly | Operator |
| Confirm forwarder delivery (when enabled) | Weekly | Operator |
| Review audited-event set (AU-2) for completeness | Annually (next: 2027-06-01) | ISSO |
| Review this procedures document | Annually (next: 2027-06-01) | ISSO |
| Review AU policy | Annually (next: 2027-06-01) | ISSO |

## 12 Records and evidence

Evidence produced by these procedures is retained as AU/SI assessment evidence:

- Audit record files (sealed envelopes when integrity is enabled) and rotated backups.
- Hash-chain verification output (`VerifyChainFiles` pass/fail).
- Generated compliance reports (read-only over the local file).
- Forwarder delivery/spool logs (when the forwarder is enabled).
- Cluster apiserver audit log (per
  [`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../../deployments/kubernetes/cluster-audit/audit-policy.yaml)).
- Unit-test output proving the emit/attribution/integrity/retention/forwarding guarantees (the
  `*_test.go` suites cited above).

Records are referenced from the SSP ([../ssp/SSP.md](../ssp/SSP.md), AU family).

## 13 References

- AU policy: [../policies/AU-policy.md](../policies/AU-policy.md)
- AU control narrative: [../AU-controls.md](../AU-controls.md)
- Audit subsystem: [`internal/audit/logger.go`](../../../internal/audit/logger.go) · [`internal/audit/schema.json`](../../../internal/audit/schema.json) · [`internal/audit/integrity.go`](../../../internal/audit/integrity.go) · [`internal/audit/redaction.go`](../../../internal/audit/redaction.go) · [`internal/audit/forward_backend.go`](../../../internal/audit/forward_backend.go)
- Admission attribution: [`internal/admission/controller.go`](../../../internal/admission/controller.go) · [`cmd/admission-webhook/main.go`](../../../cmd/admission-webhook/main.go)
- Management plane: [`internal/policymanager/manager.go`](../../../internal/policymanager/manager.go) · [`internal/policymanager/controller.go`](../../../internal/policymanager/controller.go) · [`internal/policymanager/router.go`](../../../internal/policymanager/router.go) · [`internal/policymanager/compliance.go`](../../../internal/policymanager/compliance.go) · [`cmd/dashboard/proxy.go`](../../../cmd/dashboard/proxy.go)
- Retention validation: [`internal/config/config.go`](../../../internal/config/config.go)
- Cluster audit policy: [`deployments/kubernetes/cluster-audit/audit-policy.yaml`](../../../deployments/kubernetes/cluster-audit/audit-policy.yaml)
- Operator docs: [`docs/audit/time-synchronization.md`](../../audit/time-synchronization.md) · [`docs/audit/forwarding.md`](../../audit/forwarding.md) · [`docs/audit/cluster-audit-policy.md`](../../audit/cluster-audit-policy.md)
- POA&M: [../POAM.md](../POAM.md) · Control matrix: [../control-matrix.csv](../control-matrix.csv) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (AU-1 family + SI-12); FedRAMP Moderate baseline; CIS Kubernetes Benchmark §3.2.
