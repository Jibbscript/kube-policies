# Audit Log Forwarding (AUD-WU-09, AUD-WU-10)

Controls: NIST AU-6, AU-6(3), AU-4(1)

---

## Overview

kube-policies provides two independent paths for shipping admission-webhook
audit records off the pod:

| Path | Config gate | Default | Durability |
|---|---|---|---|
| **In-process forward backend** | `audit.backend.type=forward` (app config) | Off | Disk spool + TLS replay |
| **Fluent Bit forwarder DaemonSet** | `audit.forwarder.enabled=true` (Helm values) | Off | Fluent Bit tail-DB position file |

Both paths are config-gated and **disabled by default**. Neither has been
validated against a live cluster SIEM endpoint; each has been unit-tested
against a mock TLS receiver only.

---

## Path A: In-process forward backend

`internal/audit/forward_backend.go` implements `ForwardBackend`, a `Backend`
that ships each audit record as a newline-delimited JSON line over a persistent
mTLS connection.

### Enabling

The chart's ConfigMap template currently renders `audit.backend.type` as `file`
or `stdout` only (a render-time guard rejects other values). To use the forward
backend, bypass the Helm ConfigMap by supplying a hand-crafted config Secret or
a Helm `--set-string` override that disables the guard. This is an operator-level
operation; no dedicated Helm toggle exists yet.

Application config keys (under `audit.config`, a `map[string]string`):

| Key | Required | Description |
|---|---|---|
| `forward_address` | Yes | `host:port` of the TLS log receiver |
| `forward_spool_dir` | No | Directory for the disk spool (default: `<log-dir>/spool`) |
| `forward_ca_file` | No | PEM CA bundle to trust for the receiver certificate (default: system roots) |
| `forward_tls_insecure` | No | `"true"` disables TLS verification — **testing only** |
| `forward_server_name` | No | TLS SNI / verification name override (default: host from `forward_address`) |
| `forward_dial_timeout` | No | Connection dial timeout (Go duration string, default `5s`) |

### Behavior

1. On each `Write` / `WriteRaw` call the backend attempts a live TLS delivery.
2. On any connection or write failure the record is appended to the disk spool
   (`<forward_spool_dir>/audit-forward.spool`, mode `0600`). The spool
   directory is created at startup (`0750`).
3. A background goroutine (`replayLoop`) retries spool delivery every 5 seconds.
   Records are replayed in order; a re-failure stops the pass so ordering is
   never violated.
4. On `Close()` a final drain attempt is made before the connection is torn
   down. Records that still could not be delivered remain in the spool for the
   next process start.

A transient receiver outage therefore never silently drops a record — it lands
in the spool and is replayed on recovery. This is the local-durability
guarantee of the forward backend.

### TLS requirements

The receiver must present a certificate whose CN or SAN matches `forward_address`
(or `forward_server_name`). The webhook presents no client certificate; the
receiver does not perform mutual TLS toward the webhook. Minimum TLS version
is 1.2 (`tls.VersionTLS12`); the connection inherits the Go default cipher
suite preference (prefer TLS 1.3 when both sides support it).

---

## Path B: Fluent Bit forwarder DaemonSet

`charts/kube-policies/templates/audit-forwarder-daemonset.yaml` renders a
Fluent Bit DaemonSet when `audit.forwarder.enabled=true`. It tails
`/var/log/kube-policies/audit.log` — the same path written by the `file`
backend — and forwards records to one of four configurable destinations.

### Why use the forwarder DaemonSet at scale

The admission webhook is stateless and can run with `admissionWebhook.replicaCount > 1`.
A `ReadWriteOnce` audit PVC (`audit.persistence`) can be mounted on only one
node at a time, which conflicts with multi-replica deployments that land pods
on different nodes. The forwarder DaemonSet avoids shared storage entirely:
each node runs one Fluent Bit pod that tails whatever audit log files land on
that node, then ships them off-cluster. This is the recommended durability path
for multi-replica production deployments.

### Enabling

```yaml
audit:
  forwarder:
    enabled: true
    destination:
      loki:             # choose one destination
        enabled: true
        host: "loki.monitoring.svc.cluster.local"
        port: 3100
        labels: "job=kube-policies-audit"
```

### Supported destinations

All destinations are disabled by default. Enable exactly one (or multiple, for
fan-out) via `audit.forwarder.destination.<name>.enabled=true`:

| Destination | values.yaml key | Protocol |
|---|---|---|
| Grafana Loki | `audit.forwarder.destination.loki` | HTTP push API |
| Elasticsearch / OpenSearch | `audit.forwarder.destination.elasticsearch` | Elasticsearch bulk API |
| Splunk HEC | `audit.forwarder.destination.splunk` | Splunk HTTP Event Collector |
| Syslog (RFC 5424) | `audit.forwarder.destination.syslog` | TCP (plain or TLS) |

When no destination is enabled, Fluent Bit falls back to stdout — useful for
testing that the DaemonSet starts and reads logs, but not a real forwarding
configuration.

#### Destination configuration keys

**Loki** (`audit.forwarder.destination.loki`):

| Key | Default | Description |
|---|---|---|
| `host` | `loki.monitoring.svc.cluster.local` | Loki push API hostname |
| `port` | `3100` | Loki push API port |
| `labels` | `job=kube-policies-audit` | Loki stream labels |

**Elasticsearch** (`audit.forwarder.destination.elasticsearch`):

| Key | Default | Description |
|---|---|---|
| `host` | `elasticsearch.logging.svc.cluster.local` | Elasticsearch hostname |
| `port` | `9200` | Elasticsearch port |
| `index` | `kube-policies-audit` | Index name |
| `tls` | `false` | Enable TLS to Elasticsearch |

**Splunk** (`audit.forwarder.destination.splunk`):

| Key | Default | Description |
|---|---|---|
| `host` | `splunk.logging.svc.cluster.local` | Splunk HEC hostname |
| `port` | `8088` | Splunk HEC port |
| `token` | `""` | Splunk HEC token (must be set) |
| `tls` | `true` | Enable TLS to Splunk |

**Syslog** (`audit.forwarder.destination.syslog`):

| Key | Default | Description |
|---|---|---|
| `host` | `syslog.logging.svc.cluster.local` | Syslog receiver hostname |
| `port` | `514` | Syslog receiver port |
| `mode` | `tcp` | Transport mode (`tcp` or `udp`) |

### Requires a shared audit volume

The forwarder DaemonSet tails the file audit log on a volume that **must be
shared with the webhook pods**. Under the restricted Pod Security Standard a
node-level `hostPath` tail of `/var/log/containers` is not permitted, so the
only restricted-PSS-compliant shared source is the audit PVC. The chart
therefore **requires `audit.persistence.enabled=true`** (with a cross-node
`ReadWriteMany` access mode for a multi-replica webhook) when the forwarder is
enabled — `helm template` fails fast with a remediation message otherwise,
rather than deploying a forwarder that tails an empty per-pod directory and
ships nothing. To ship via stdout instead, set the webhook audit backend to
`stdout` and use a cluster-wide log collector rather than this DaemonSet.

### Security posture

The forwarder DaemonSet is restricted-PSS-compliant. It carries
`app.kubernetes.io/component: admission-webhook` so the
`test/policy/restricted-pss.rego` policy evaluates it; because the forwarder is
**default-off** it is not part of the default CI render, so this is verified
on-demand (`conftest test --namespace restricted.pss` over a render with
`audit.forwarder.enabled=true`), not by a standing CI gate. The enforced
controls are:

- `seccompProfile: RuntimeDefault`
- `runAsNonRoot: true`, `runAsUser/runAsGroup: 65534` (nobody)
- `readOnlyRootFilesystem: true` (Fluent Bit state/buffer via separate `emptyDir`)
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- No host namespaces (`hostNetwork`, `hostPID`, `hostIPC` all absent)
- CPU/memory requests and limits on every container

---

## Architectural guidance: which path to use

| Scenario | Recommended path |
|---|---|
| Single-replica webhook, simple setup | In-process forward backend (Path A) |
| Multi-replica webhook (replicaCount > 1) | Fluent Bit forwarder DaemonSet (Path B) |
| Air-gapped cluster with no SIEM | `audit.backend.type=file` + `audit.persistence` (local only) |
| Existing Fluent Bit / Fluentd DaemonSet | Point it at `/var/log/kube-policies/audit.log`; disable Path B |

A `ReadWriteOnce` PVC (`audit.persistence`) **cannot** be shared across nodes.
If replicaCount > 1 and replicas land on different nodes, the second pod will
fail to mount the PVC. Use Path B (forwarder DaemonSet) or a `ReadWriteMany`
StorageClass to avoid this.

---

## Source IP attribution note

The `source_ip` field in each audit record reflects the webhook's direct HTTP
peer — typically the kube-apiserver or an intermediate proxy — **not** the
originating client IP. The Kubernetes admission webhook protocol does not
forward the original caller's IP to the webhook server. Operators correlating
source IPs must use the kube-apiserver's own audit log (see
`docs/audit/cluster-audit-policy.md`) to recover the originating client address
for a given `requestID`.

---

## Limitations

- kube-policies is a pre-1.0 proof-of-concept; no ATO has been issued.
- The forward backend (Path A) has been unit-tested against a mock TLS receiver
  only; no live-cluster forwarding validation has been performed.
- The Helm chart's ConfigMap template does not yet expose a `forward` backend
  type toggle; using Path A requires a manual config override.
- Destination hostnames in values.yaml are examples and must be replaced with
  real service addresses before enabling.

---

## References

- `internal/audit/forward_backend.go` — ForwardBackend implementation
- `internal/audit/logger.go` — createBackend() backend dispatch
- `internal/config/config.go` — AuditConfig, validateAudit()
- `charts/kube-policies/templates/audit-forwarder-daemonset.yaml` — DaemonSet + ConfigMap
- `charts/kube-policies/values.yaml` — `audit.forwarder.*` stanza (line 607)
