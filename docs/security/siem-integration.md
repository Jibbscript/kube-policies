---
title: "SIEM Integration — Kube-Policies (KP)"
controls: "AU-6, AU-9(3), SI-4"
version: "0.1.0"
status: "Draft"
owner: "ISSO (TBD — assign before assessment)"
approver: "System Owner (TBD — assign before assessment)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# SIEM Integration — Kube-Policies (KP)

> IRM-WU-13 · NIST SP 800-53 Rev 5: AU-6, AU-9(3), SI-4 · FedRAMP Moderate baseline
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: ISSO (TBD — assign before assessment) · Approver: System Owner (TBD — assign before assessment)

This document describes the opt-in log-forwarding path that ships Kube-Policies audit
events to an external Security Information and Event Management (SIEM) system. It covers
the component architecture, configuration values, delivery semantics, and the data it
carries. Runtime anomaly detection (Falco, NetworkPolicy) that also forwards findings to
the SIEM is covered in [docs/security/runtime-detection.md](runtime-detection.md).

## 1 Architecture overview

Kube-Policies uses a **file-backend-plus-forwarder** architecture for SIEM integration:

```
admission-webhook (pod)
  └─ internal/audit/logger.go
       └─ file backend → audit.log (JSON-lines, pod-local or shared PVC)
            └─ audit.forwarder DaemonSet (Fluent Bit)
                 └─ TLS → SIEM endpoint
                          (Loki / Elasticsearch / OpenSearch / Splunk HEC / syslog RFC 5424)
```

**Why file-backend-plus-forwarder, not in-process delivery.** An earlier design considered
an in-process Elasticsearch client inside the webhook. That approach was removed because:
- A blocked or slow SIEM connection inside the hot admission path risks adding latency or
  causing silent log drops without operator visibility.
- The file backend is the single durable buffer; the forwarder adds at-least-once delivery
  on top, with its own retry and backpressure mechanisms (Fluent Bit storage.type=filesystem).
- Operational concerns (credentials, endpoint changes, SIEM downtime) are fully decoupled
  from the webhook binary.

The in-process Elasticsearch backend **was removed**. All off-cluster log shipping goes
through the file backend and the forwarder.

## 2 The audit file backend

### 2.1 What it records

The file backend (`internal/audit`) writes one JSON-lines record per audit event to the
configured log file. Every record has the event type `PolicyDecision` and the following
fields (representative; full schema in `internal/audit/logger.go`):

| Field | Description |
|---|---|
| `timestamp` | RFC3339 UTC timestamp of the admission decision |
| `event_type` | Always `PolicyDecision` for admission-webhook events |
| `request_uid` | `AdmissionReview.Request.UID` — ties the record to the apiserver audit log |
| `operation` | Kubernetes admission operation: `CREATE`, `UPDATE`, `DELETE`, `CONNECT` |
| `resource` | `group/version/resource` of the object under review |
| `namespace` | Namespace of the object (empty for cluster-scoped) |
| `name` | Name of the object |
| `username` | `UserInfo.Username` of the requesting principal |
| `decision` | `allow`, `deny`, or `error` |
| `policy_name` | The Policy that produced the decision (if applicable) |
| `reason` | Human-readable decision rationale |
| `integrity_hash` | HMAC-SHA256 chain link (tamper-evident log, AU-9) |

### 2.2 Metrics

Audit pipeline health is visible via Prometheus metrics emitted by
`internal/metrics/collector.go`:

| Metric | Labels | Description |
|---|---|---|
| `kube_policies_audit_events_total` | `event_type`, `status` | Counter: events written (`ok`), dropped (`dropped`), or write-errored (`write_error`) |
| `kube_policies_audit_buffer_size` | — | Gauge: current in-process buffer depth |

Security alerts (`KubePoliciesAuditEventsDropped`, `KubePoliciesAuditWriteErrors`,
`KubePoliciesAuditBufferSaturated`) fire when the pipeline degrades; definitions are in
[charts/kube-policies/files/alerts/security.yaml](../../charts/kube-policies/files/alerts/security.yaml).

### 2.3 File location

The audit log is written to the path configured in `audit.logPath` (default:
`/var/log/kube-policies/audit.log`). When `audit.persistence.enabled: true`, a PVC
mounts at that path; otherwise it is pod-ephemeral. The forwarder DaemonSet mounts the
same path (or the host path on the node) to tail the file.

## 3 The log-forwarding DaemonSet

The forwarder is an **opt-in** Fluent Bit DaemonSet deployed alongside the admission-webhook
pods. It is disabled by default (`audit.forwarder.enabled: false`).

### 3.1 Enabling the forwarder

```yaml
# values.yaml excerpt
audit:
  forwarder:
    enabled: true        # enable the DaemonSet
    destination:
      # Enable exactly ONE backend:
      splunk:
        enabled: true
        host: "splunk-hec.siem.example.com"
        port: 8088
        token: ""        # set via existingSecret or --set
        tls: true
```

The Helm key path is `audit.forwarder.*`. Enabling `audit.forwarder.enabled: true`
without configuring a destination will render a forwarder with no active output plugin —
logs will be buffered on disk but not forwarded.

### 3.2 Supported destinations

| Backend | Values key | Notes |
|---|---|---|
| **Loki** (push API) | `audit.forwarder.destination.loki` | HTTP push; labels configurable |
| **Elasticsearch / OpenSearch** | `audit.forwarder.destination.elasticsearch` | `tls: true` recommended for production |
| **Splunk HEC** | `audit.forwarder.destination.splunk` | TLS on by default; token from Secret |
| **Syslog** (RFC 5424 over TCP/TLS) | `audit.forwarder.destination.syslog` | Mode `tcp` or `tls` |

Only one destination should be active at a time (set `enabled: true` on exactly one).
Multiple simultaneous destinations are unsupported.

### 3.3 TLS requirements

For FedRAMP Moderate compliance all SIEM endpoints **must** use TLS. Set `tls: true` on
the destination. The forwarder trusts the system CA bundle; supply a custom CA via
`audit.forwarder.destination.<backend>.caFile` if the SIEM uses a private PKI.

## 4 At-least-once delivery semantics

Fluent Bit provides **at-least-once** delivery via filesystem buffering:

- `storage.type filesystem` buffers chunks on disk before forwarding.
- On retry, the same chunk is re-sent; the SIEM must deduplicate on `request_uid` if
  duplicate events are a concern.
- If the SIEM endpoint is unreachable, chunks accumulate on disk up to the configured
  `storage.total_limit_size`. When that limit is reached, **oldest chunks are dropped** to
  protect the forwarder itself from running out of disk. This is the only scenario in which
  events can be permanently lost; operators are alerted via `KubePoliciesAuditBufferSaturated`
  before this condition is reached.
- **There is no exactly-once guarantee.** The SIEM should treat `request_uid` as an
  idempotency key.

## 5 Security controls

| Control | Implementation |
|---|---|
| **AU-6** (Audit review, analysis, reporting) | SIEM receives all `PolicyDecision` events for correlation and review. |
| **AU-9(3)** (Cryptographic protection of audit records) | Tamper-evident hash chain in each audit record (`integrity_hash`); the file backend seals records with HMAC-SHA256. |
| **SI-4** (Information system monitoring) | Audit drop and write-error alerts feed the monitoring pipeline; Falco rules covering the forwarder are in [docs/security/runtime-detection.md](runtime-detection.md). |
| **Credential protection** | SIEM credentials (Splunk token, Elasticsearch password) are sourced from a Kubernetes Secret; never embedded in values files committed to version control. |
| **Network segmentation** | The forwarder's egress to the SIEM endpoint is permitted by the egress NetworkPolicy; all other egress is denied by default. See [docs/security/runtime-detection.md](runtime-detection.md) for the NetworkPolicy scope. |

## 6 Operational guidance

**Log rotation.** The file backend does not rotate the audit log; configure `logrotate` or
an equivalent if using pod-ephemeral storage. With PVC-backed persistence and a forwarder,
the forwarder tails the log continuously — truncation without coordination can cause re-reads.

**Disabling the forwarder at runtime.** Disabling `audit.forwarder.enabled` removes the
DaemonSet; in-flight buffer chunks on disk are lost. This is a control degradation; record
as a deviation in the [POA&M](../compliance/POAM.md) and re-enable promptly.

**SIEM index / log-group naming.** Standardize the destination index or label
(e.g. `kube-policies-audit`) so ConMon queries in the SIEM are reproducible.

## 7 Annual review

This document is reviewed at least **annually** (next review: **2027-06-01**) and whenever
the forwarder configuration, audit schema, or destination changes.

## 8 References

- Alert definitions (audit drop/buffer): [charts/kube-policies/files/alerts/security.yaml](../../charts/kube-policies/files/alerts/security.yaml)
- Audit metrics: `internal/metrics/collector.go` (`kube_policies_audit_events_total`, `kube_policies_audit_buffer_size`)
- Audit implementation: `internal/audit/logger.go`
- Runtime detection and NetworkPolicy: [docs/security/runtime-detection.md](runtime-detection.md)
- Continuous monitoring plan: [docs/security/continuous-monitoring-plan.md](continuous-monitoring-plan.md)
- Incident response plan: [docs/security/incident-response-plan.md](incident-response-plan.md)
- On-call escalation: [docs/security/on-call-escalation.md](on-call-escalation.md)
- POA&M: [docs/compliance/POAM.md](../compliance/POAM.md)
- NIST SP 800-53 Rev 5: AU-6, AU-9, AU-9(3), SI-4; FedRAMP Moderate baseline.
