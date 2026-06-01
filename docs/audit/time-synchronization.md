# Audit Timestamp Accuracy and Time Synchronization (AUD-WU-03)

Controls: NIST AU-8, AU-8(1)

---

## Overview

Every audit record emitted by the admission webhook carries two RFC 3339 UTC
timestamps (AUD-WU-02, NIST AU-8):

| Field | Populated from | Purpose |
|---|---|---|
| `request_received_timestamp` | `time.Now().UTC()` at controller entry | When the request arrived at the webhook |
| `stage_timestamp` | `time.Now().UTC()` when the record is flushed | When the audit record was written |

Both fields are set in `internal/audit/logger.go` (`LogDecision`) and are
always expressed in UTC (`time.Time.UTC()`). The `timestamp` top-level field
also records the handler-entry time for backward compatibility with consumers
that predate the dual-timestamp fields.

---

## Container clocks track the host

Kubernetes containers share the host kernel's clock (`CLOCK_REALTIME`). There
is no per-container clock source. Accurate timestamps in audit records therefore
depend entirely on the accuracy of the underlying node clock — the webhook
process has no independent time source.

---

## Node time-synchronization requirement

Every cluster node MUST run a time-synchronization daemon synchronized to a
reliable NTP source. Accepted implementations:

- **chrony** (recommended for Linux nodes — default on most modern distros)
- **systemd-timesyncd** (lightweight; adequate for non-HA single-node setups)
- **ntpd** (legacy; still acceptable if already deployed)

Managed Kubernetes services (EKS, GKE, AKS) synchronize node time
automatically via their hypervisor layer; verify this with your cloud
provider's documentation before relying on it.

### Minimum configuration requirements

| Parameter | Requirement |
|---|---|
| NTP stratum | Stratum 3 or better (stratum 1 or 2 preferred) |
| Maximum allowable offset | ≤ 1 second relative to UTC |
| Daemon restart on large step | Enabled (so a large drift is corrected immediately, not slewed slowly) |

### Verification

```bash
# chrony
chronyc tracking | grep "System time\|RMS offset"

# systemd-timesyncd
timedatectl show-timesync --all

# ntpd
ntpq -p
```

---

## Skew tolerance

The webhook does not apply a hard clock-skew cutoff to inbound requests — it
records the timestamp it observes and trusts the node clock. Operators are
responsible for monitoring node clock drift at the infrastructure level.

For SIEM correlation, a skew tolerance of **±1 second** between the webhook's
`request_received_timestamp` and the kube-apiserver's own audit timestamp for
the same event is considered acceptable. Larger skew indicates a node clock
problem and should trigger an alert.

---

## CIS / NIST mapping

| Control | Requirement | How met |
|---|---|---|
| NIST AU-8 | Timestamps on audit records | `request_received_timestamp` + `stage_timestamp` in every `PolicyDecision` record |
| NIST AU-8(1) | Synchronize internal clocks | Node NTP/chrony prerequisite (this document) |
| CIS 2.2 (node hardening) | Time synchronization | NTP daemon on every node |

---

## Limitations

- kube-policies is a pre-1.0 proof-of-concept; no ATO has been issued.
- The webhook has no mechanism to detect or compensate for node clock drift; it
  records `time.Now()` unconditionally.
- Dual-timestamp fields (`request_received_timestamp`, `stage_timestamp`) use
  `omitempty` — non-decision events (system, config-change) that predate
  AUD-WU-02 may carry only the top-level `timestamp` field.

---

## References

- `internal/audit/logger.go` — `LogDecision()` dual-timestamp logic
- `internal/audit/logger.go` — `Event` struct fields `RequestReceivedTimestamp`, `StageTimestamp`
- NIST SP 800-92 — Guide to Computer Security Log Management
