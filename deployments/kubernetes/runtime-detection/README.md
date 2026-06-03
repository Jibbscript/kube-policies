# Runtime Detection — Standalone Falco Deployment

> NIST SP 800-53 Rev 5: SI-4, SI-4(2), SI-4(4), SC-7  
> IRM-WU-23 · CIS Kubernetes Benchmark 5.3.2  
> Status: OPT-IN — not enabled by default. No ATO. Unauthorized PoC.

This directory contains standalone (non-Helm) Kubernetes manifests for deploying
a Falco DaemonSet that consumes the kube-policies runtime-detection ruleset. It is
the direct alternative to the Helm chart's `runtimeDetection.enabled=true` toggle.

**Target workloads:** `admission-webhook` and `policy-manager` in the
`kube-policies-system` namespace.

---

## Deployment options

### Option A — Helm chart toggle (recommended for chart-managed installations)

```bash
helm upgrade kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --reuse-values \
  --set runtimeDetection.enabled=true
```

This creates a ConfigMap (`<release>-kube-policies-falco-rules`) in the
`kube-policies-system` namespace. An existing Falco DaemonSet must be configured to
mount this ConfigMap as an additional rules file. The Helm chart does **not** deploy
Falco itself — Falco is cluster infrastructure.

See `charts/kube-policies/templates/falco-rules-configmap.yaml` and
`docs/security/runtime-detection.md §Deployment options`.

### Option B — Standalone kustomize (this directory)

Use this path when:
- The cluster is not managed by the kube-policies Helm chart, **or**
- You want a self-contained Falco deployment scoped to the kube-policies workloads,
  **or**
- You prefer GitOps (Flux/ArgoCD) over Helm for runtime-detection infrastructure.

```bash
# Dry-run first:
kubectl apply -k deployments/kubernetes/runtime-detection/ --dry-run=client

# Apply:
kubectl apply -k deployments/kubernetes/runtime-detection/
```

**Prerequisites:**

1. Kernel 5.8+ (for the eBPF CO-RE probe) OR the Falco kernel module driver.  
   For kernels < 5.8, edit `daemonset.yaml` to change `FALCO_DRIVER_CHOICE=module`.
2. A CNI plugin that enforces NetworkPolicy (Calico, Cilium, Weave, etc.) — required
   for the NetworkPolicy-based egress controls to be effective alongside Falco.
3. The `kube-policies-system` namespace already exists (created by Helm/base manifests
   before applying this overlay).

---

## Files

| File | Purpose |
|---|---|
| `namespace.yaml` | `falco-system` namespace with `pod-security.kubernetes.io/enforce: privileged` (required for Falco's eBPF/module driver). |
| `rbac.yaml` | ServiceAccount, ClusterRole (least-privilege: read-only pod/node/namespace/event metadata), ClusterRoleBinding, and a namespace-scoped Role for ConfigMap hot-reload. |
| `configmap.yaml` | Two ConfigMaps: `kube-policies-falco-rules` (embeds `monitoring/falco/kube-policies-rules.yaml` verbatim) and `falco-config` (minimal `falco.yaml` pointing to the rules overlay). |
| `daemonset.yaml` | Falco DaemonSet — privileged, `hostPID: true`, eBPF driver loader init container, rules and config mounted from the ConfigMaps above. |
| `kustomization.yaml` | Kustomize entry point; applies all four manifests with common labels/annotations. |

---

## Image pinning

The DaemonSet references `falcosecurity/falco-no-driver:0.39.2`. Before applying
to a production or assessment cluster:

1. Retrieve the current stable release from
   <https://github.com/falcosecurity/falco/releases>.
2. Pin by digest:

   ```bash
   docker pull falcosecurity/falco-no-driver:0.39.2
   docker inspect --format='{{index .RepoDigests 0}}' \
     falcosecurity/falco-no-driver:0.39.2
   ```

3. Update the `image:` field in `daemonset.yaml` to
   `falcosecurity/falco-no-driver:0.39.2@sha256:<digest>`.

Look for `TODO-PIN` comments in `daemonset.yaml` for both the main container and
the driver-loader init container.

---

## Rules — single source of truth

The canonical Falco rules file is:

```
monitoring/falco/kube-policies-rules.yaml
```

`configmap.yaml` embeds that content verbatim. When updating rules:

```bash
# Re-sync the embedded content (copy rules into configmap.yaml's data section).
# A CI step that diffs the two files is recommended.
diff monitoring/falco/kube-policies-rules.yaml \
  <(kubectl get cm kube-policies-falco-rules -n falco-system \
    -o jsonpath='{.data.kube-policies-rules\.yaml}')
```

The Helm chart path (`charts/kube-policies/files/falco/kube-policies-rules.yaml`)
is separately kept in sync via the chart's `Files.Get` template.

---

## Alerting path: Falco → falcosidekick → Slack / Alertmanager

Falco emits findings as JSON to stdout. Two forwarding paths are supported:

### Path 1 — falcosidekick sidecar (recommended)

Deploy [falcosidekick](https://github.com/falcosecurity/falcosidekick) alongside
the Falco DaemonSet. falcosidekick listens on the Falco gRPC Unix socket
(`/run/falco/falco.sock`) and fans findings out to multiple outputs simultaneously.

Enable gRPC in `configmap.yaml`'s `falco.yaml` section:

```yaml
grpc:
  enabled: true
  bind_address: "unix:///run/falco/falco.sock"
  threadiness: 0

grpc_output:
  enabled: true
```

Then deploy falcosidekick configured for your outputs:

```yaml
# falcosidekick config excerpt (values for falcosidekick Helm chart):
config:
  slack:
    webhookurl: "https://hooks.slack.com/services/..."
    minimumpriority: warning
  alertmanager:
    hostport: "http://alertmanager.monitoring.svc:9093"
    minimumpriority: warning
    # Route kube-policies findings to the security receiver:
    extraheaderslist: 'X-Scope-OrgID:kube-policies-runtime'
  webhook:
    address: "https://your-siem-endpoint/falco"
    minimumpriority: info
    # All findings tagged kube-policies-* appear in the SIEM alongside
    # PolicyDecision audit events — see docs/security/siem-integration.md.
```

Severity routing:

| Falco priority | falcosidekick minimum | Recommended action |
|---|---|---|
| CRITICAL | warning | Immediate SEV1 page — see IR plan §3.1 |
| ERROR | warning | SEV2 investigation within 4 h |
| WARNING | warning | SEV2/3 review within 1 business day |
| INFO | info | SIEM only — no alert |

### Path 2 — Fluent Bit tail + SIEM forwarding

If falcosidekick is not deployed, the existing Fluent Bit audit forwarder DaemonSet
(configured in `audit.forwarder` values) can be extended to tail Falco's stdout
JSON output from the node log path:

```ini
[INPUT]
    Name              tail
    Path              /var/log/containers/falco-*.log
    Parser            json
    Tag               falco.*
    Refresh_Interval  5

[FILTER]
    Name   grep
    Match  falco.*
    Regex  rule kube-policies-

[OUTPUT]
    Name              http
    Match             falco.*
    Host              ${SIEM_HOST}
    Port              ${SIEM_PORT}
    TLS               On
    TLS.Verify        On
    URI               /falco
```

See `docs/security/siem-integration.md` for the full forwarder configuration.

---

## Incident linkage

Runtime detection findings link into the existing incident response workflow:

- **Incident Response Plan:** `docs/security/incident-response-plan.md`
- **Relevant runbooks:**
  - `docs/security/runbooks/fail-open-event.md` — if a Falco finding correlates
    with a fail-open admission event
  - `docs/security/runbooks/webhook-outage.md` — if the finding indicates
    compromise of the admission-webhook pod
  - `docs/security/runbooks/dos-response.md` — if unexpected process/network
    activity is part of a DoS or resource-exhaustion attack

Falco CRITICAL findings (`kube-policies shell in container`,
`kube-policies sensitive mount or privilege escalation`) map to **SEV1** per the IR
plan §3.1 and should trigger an immediate page to the incident commander.

---

## Tuning (reducing false positives)

### Allowlist expected processes

If a sidecar or init container legitimately runs a process that triggers
`kube-policies unexpected process spawned`, add it to the `kube_policies_main_procs`
macro in `monitoring/falco/kube-policies-rules.yaml`:

```yaml
- macro: kube_policies_main_procs
  condition: (proc.name in (admission-webhook, policy-manager, dashboard, <your-proc>))
```

Then re-sync `configmap.yaml` (see Rules section above).

### Allowlist expected network destinations

If the SIEM endpoint uses a non-standard port (not 443, 6443, 8081, 8443, 53),
add it to the `kube-policies unexpected outbound connection` rule's `fd.rport` list:

```yaml
and not fd.rport in (443, 6443, 8081, 8443, 53, <your-siem-port>)
```

Alternatively, add the SIEM IP to the `fd.rip` allowlist. Per the P9 lessons:
key on the **destination** (`fd.rport`/`fd.rip`), not the source port — source-port
allowlisting produces constant false positives and misses actual exfiltration.

### Reduce noise from init containers

Falco applies rules to all containers in a pod, including init containers. If an
init container legitimately runs a shell (e.g., a permission-fixer), scope the
`kube_policies_pods` macro more tightly using `container.name`:

```yaml
- macro: kube_policies_pods
  condition: >
    (k8s.ns.name = "kube-policies-system" or
     container.image.repository contains "kube-policies")
    and not container.name in (init-permissions, init-migrate)
```

### NIST references

- **SI-4** — Information System Monitoring: deploy sensors, collect indicators, alert.
- **SI-3** — Malicious Code Protection: detect and respond to malicious code (shells,
  unexpected executables) in the runtime environment.
- **SP 800-190** §4.4 — Container Runtime Threats: monitor for unexpected processes,
  filesystem modifications, and unusual network activity from containers.
