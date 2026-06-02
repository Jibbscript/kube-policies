---
title: "Runtime Detection — Kube-Policies (KP)"
controls: "SI-4, SI-4(2), SI-4(4), SC-7"
version: "0.1.0"
status: "Draft"
owner: "ISSO (TBD — assign before assessment)"
approver: "System Owner (TBD — assign before assessment)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Runtime Detection — Kube-Policies (KP)

> IRM-WU-23 · NIST SP 800-53 Rev 5: SI-4, SI-4(2), SI-4(4), SC-7 · CIS Benchmark 5.3.2
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: ISSO (TBD — assign before assessment) · Approver: System Owner (TBD — assign before assessment)

This document describes the runtime detection coverage for Kube-Policies:

1. **NetworkPolicy** — restricts network ingress and egress for KP pods to the minimum
   required surfaces.
2. **Falco rules** — flag unexpected process or network activity originating from KP pods
   and forward findings to the SIEM.

Both controls are **opt-in** and depend on cluster infrastructure (a CNI plugin that
enforces NetworkPolicy, and the Falco DaemonSet deployed separately). This document
describes the detection design and SIEM forwarding path; the NetworkPolicy manifests and
Falco rule file are authored separately and referenced here.

## 1 NetworkPolicy coverage

### 1.1 Design intent (SC-7, SI-4(4))

The admission-webhook and policy-manager pods operate as a fail-closed gatekeeper for all
cluster admission traffic. Unexpected network connections from these pods — particularly
unexpected egress — are high-confidence indicators of compromise. A default-deny
NetworkPolicy with explicit allow rules enforces the minimum required surfaces and satisfies
CIS Benchmark 5.3.2 (namespace-level network policy).

### 1.2 Ingress rules

| Pod selector | Allowed ingress source | Port | Rationale |
|---|---|---|---|
| `app.kubernetes.io/component=admission-webhook` | Kubernetes apiserver (via `namespaceSelector: kubernetes.io/metadata.name=kube-system`) | `8443/TCP` (webhook TLS) | Webhook admission requests originate from the apiserver only. |
| `app.kubernetes.io/component=admission-webhook` | Prometheus (monitoring namespace) | `8080/TCP` (metrics) | Metrics scrape by ServiceMonitor. |
| `app.kubernetes.io/component=policy-manager` | Internal (same namespace) | `8081/TCP` (policy API) | Webhook-to-policy-manager registry queries. |
| `app.kubernetes.io/component=policy-manager` | Prometheus (monitoring namespace) | `8082/TCP` (metrics) | Metrics scrape. |

All other ingress is denied by the default-deny NetworkPolicy
(`charts/kube-policies/templates/networkpolicy-default-deny.yaml`).

### 1.3 Egress rules

| Pod selector | Allowed egress destination | Port | Rationale |
|---|---|---|---|
| All KP pods | kube-dns (UDP/TCP) | `53` | DNS resolution required for all components. |
| `admission-webhook` | Kubernetes apiserver | `443/TCP` | CRD list/watch, leader election lease. |
| `policy-manager` | Kubernetes apiserver | `443/TCP` | CRD reconciliation (Policy, PolicyException). |
| All KP pods | SIEM endpoint (configurable; `logForwarding.endpoint`) | Configurable TLS port | Audit log forwarding via Fluent Bit forwarder. |

All other egress is denied. In particular:
- No egress to the internet (no image pulls from pods; images are pulled at schedule time
  by the kubelet, not by the running pod).
- No egress to other workload namespaces.
- No unexpected egress to internal cluster services outside the apiserver path.

Relevant templates:

- `charts/kube-policies/templates/networkpolicy-default-deny.yaml` — namespace-wide default deny
- `charts/kube-policies/templates/networkpolicy-ingress-webhook.yaml` — apiserver ingress
- `charts/kube-policies/templates/networkpolicy-ingress-metrics.yaml` — Prometheus scrape ingress
- `charts/kube-policies/templates/networkpolicy-egress-apiserver.yaml` — apiserver egress
- `charts/kube-policies/templates/networkpolicy-egress-dns.yaml` — DNS egress
- `charts/kube-policies/templates/networkpolicy-egress-internal.yaml` — intra-namespace (webhook→policy-manager)

> **CNI dependency.** NetworkPolicy enforcement requires a CNI plugin that supports it
> (Calico, Cilium, Weave, etc.). On clusters without a supporting CNI the policies are
> accepted by the apiserver but **not enforced** — verify CNI support before relying on
> these policies for isolation.

## 2 Falco runtime detection

### 2.1 Design intent (SI-4, SI-4(2))

Falco provides host-level syscall inspection that is independent of Kubernetes admission
control and NetworkPolicy. Because KP pods run `gcr.io/distroless/static` images with no
shell and no package manager, any `execve` syscall from a KP pod is unexpected and
indicative of compromise or image tampering. Similarly, unexpected outbound network
connections indicate data exfiltration or C2 activity.

### 2.2 Rule file

The Kube-Policies Falco rules are defined in
`monitoring/falco/kube-policies-rules.yaml`. The rule file is opt-in — it must be loaded
into the Falco DaemonSet configuration alongside the default ruleset. The rule file is not
deployed by the Helm chart (Falco is cluster infrastructure, not a KP component).

### 2.3 Detection coverage

The Falco ruleset covers the following threat scenarios:

| Rule name | Condition | Severity | Rationale |
|---|---|---|---|
| `kube-policies unexpected exec` | `execve` syscall from any process in a KP pod | CRITICAL | KP pods use distroless images — no shell should ever exec. Any exec is a sign of container escape or image tampering. |
| `kube-policies shell in pod` | `shell_procs` spawned inside a KP pod container | CRITICAL | Companion to the exec rule; catches interactive shells. |
| `kube-policies unexpected outbound network` | Network connection from a KP pod to a destination not in the allowed egress list | HIGH | Unexpected egress (beyond apiserver, DNS, SIEM) indicates exfiltration or C2. |
| `kube-policies unexpected inbound network` | Inbound connection to a KP pod on a non-webhook, non-metrics port | HIGH | Unexpected ingress may indicate port scanning or lateral movement. |
| `kube-policies write to sensitive path` | File write to `/etc/`, `/usr/`, `/bin/`, `/sbin/` from a KP pod | HIGH | Distroless containers should not write to system paths; a write indicates code injection. |
| `kube-policies read sensitive credentials` | Read of `/var/run/secrets/kubernetes.io/serviceaccount/token` outside the expected startup window | MEDIUM | The service account token should be read once at startup; sustained reads suggest credential harvesting. |

### 2.4 SIEM forwarding path (SI-4, AU-6)

Falco is configured to output findings as JSON to `stdout` (or via the Falco gRPC/webhook
output plugin). The Fluent Bit forwarder DaemonSet (the same instance described in
[docs/security/siem-integration.md](siem-integration.md)) tails the Falco output and
forwards findings to the same SIEM endpoint as the KP audit log. This provides correlated
visibility in a single SIEM index:

```
Falco DaemonSet → stdout JSON
  └─ Fluent Bit (additional input: falco log path)
       └─ TLS → SIEM endpoint
                (same destination as audit.forwarder)
```

Findings appear in the SIEM with `source: falco` and `rule: kube-policies-*` tags for
easy filtering alongside `PolicyDecision` audit events.

> **Prerequisite.** Falco must be deployed to the cluster independently. The Kube-Policies
> Helm chart does not deploy Falco. The rule file at
> `monitoring/falco/kube-policies-rules.yaml` must be loaded by the operator into the Falco
> rule-file configuration before detection is active.

## 3 Opt-in summary

| Control | Chart value or prerequisite | Default |
|---|---|---|
| NetworkPolicy (default-deny + allow rules) | Deployed unconditionally when `networkPolicy.enabled: true` (default: `true` — verify `values.yaml`) | On (verify per-environment CNI support) |
| Falco rule file | Loaded by operator into Falco DaemonSet — NOT deployed by chart | Off (manual load required) |
| Falco SIEM forwarding | `audit.forwarder.enabled: true` + Falco output configured as Fluent Bit input | Off (requires forwarder enabled) |

## 4 Alert integration

When Falco findings are forwarded to the SIEM, the SIEM should be configured to alert on:

- Any `kube-policies unexpected exec` or `kube-policies shell in pod` finding → immediate
  SEV1 escalation per [docs/security/on-call-escalation.md](on-call-escalation.md).
- Any `kube-policies unexpected outbound network` finding → SEV1 if during normal
  operations (no maintenance window), SEV2 otherwise.
- Falco finding volume spike → forward to Prometheus via the Falco metrics exporter and
  alert via Alertmanager.

## 5 Deployment options

Two mutually exclusive paths exist for loading the kube-policies Falco rules. Choose
one per cluster.

### 5.1 Option A — Helm chart toggle

When the kube-policies control plane is already managed by the Helm chart, enable the
opt-in `runtimeDetection` flag:

```bash
helm upgrade kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --reuse-values \
  --set runtimeDetection.enabled=true
```

This renders `charts/kube-policies/templates/falco-rules-configmap.yaml`, creating a
ConfigMap (`<release>-kube-policies-falco-rules`) in the kube-policies namespace. An
existing Falco DaemonSet must be configured to mount this ConfigMap as an additional
rules file. The Helm chart does **not** deploy Falco itself — Falco is cluster
infrastructure deployed separately.

Default: `runtimeDetection.enabled: false` (off).

### 5.2 Option B — Standalone kustomize manifests

For clusters not managed by the kube-policies Helm chart, or for GitOps workflows
(Flux, ArgoCD), use the standalone manifests:

```
deployments/kubernetes/runtime-detection/
├── namespace.yaml      # falco-system namespace (privileged PSS label required)
├── rbac.yaml           # ServiceAccount, ClusterRole (read-only), ClusterRoleBinding,
│                       # namespace-scoped Role for ConfigMap hot-reload
├── configmap.yaml      # kube-policies-falco-rules + falco-config ConfigMaps
├── daemonset.yaml      # Falco DaemonSet (eBPF driver, hostPID, privileged)
├── kustomization.yaml  # Kustomize entry point
└── README.md           # Deployment, image pinning, alerting, tuning guidance
```

Apply:

```bash
# Dry-run (YAML structural validation — no live cluster required):
yq eval '.' deployments/kubernetes/runtime-detection/*.yaml > /dev/null

# Apply:
kubectl apply -k deployments/kubernetes/runtime-detection/
```

The standalone manifests embed the same canonical rules file
(`monitoring/falco/kube-policies-rules.yaml`) and are kept in sync manually. A CI
freshness diff is recommended to catch divergence.

See `deployments/kubernetes/runtime-detection/README.md` for full deployment,
image-pinning, and tuning guidance.

> **This control is OPT-IN and is not enabled by default.** Neither path is active
> unless explicitly applied. No Falco deployment is present in the unauthorized PoC
> state of this repository.

## 6 Alerting and incident linkage

### 6.1 Alerting path

Falco emits findings as JSON to stdout. Two forwarding paths are supported:

**Path 1 — falcosidekick (recommended)**

```
Falco DaemonSet (stdout JSON)
  └─ falcosidekick (gRPC Unix socket: /run/falco/falco.sock)
       ├─ Slack webhook  (CRITICAL/ERROR findings → immediate page)
       ├─ Alertmanager   (http://alertmanager.monitoring.svc:9093)
       └─ SIEM HTTP/TLS  (same endpoint as audit.forwarder)
```

Enable gRPC in `configmap.yaml`'s `falco.yaml` section and deploy falcosidekick with
Slack webhook URL, Alertmanager hostport, and SIEM webhook address configured.
See `deployments/kubernetes/runtime-detection/README.md §Alerting path` for full
configuration snippets.

**Path 2 — Fluent Bit tail**

Extend the existing audit Fluent Bit forwarder DaemonSet (`audit.forwarder`) to tail
`/var/log/containers/falco-*.log` with a `grep` filter on `rule kube-policies-` and
forward to the same SIEM endpoint. See `docs/security/siem-integration.md` for the
forwarder configuration.

### 6.2 Severity routing

| Falco priority | Recommended action |
|---|---|
| CRITICAL | Immediate SEV1 page — incident commander + security. See IR plan §3.1. |
| ERROR | SEV2 — investigate within 4 hours. |
| WARNING | SEV2/3 — review within 1 business day. |
| INFO | SIEM only — no alert. |

### 6.3 Incident response linkage

Runtime detection findings feed into the existing incident response workflow:

- **Incident Response Plan:** [docs/security/incident-response-plan.md](incident-response-plan.md) — §3.1 (SEV1 criteria: attacker-controlled admission webhook), §5 (scenario table), §6.4 (post-incident review).
- **Runbooks:**
  - [runbooks/fail-open-event.md](runbooks/fail-open-event.md) — correlate Falco findings with fail-open admission events.
  - [runbooks/webhook-outage.md](runbooks/webhook-outage.md) — if a Falco finding indicates compromise of the admission-webhook pod.
  - [runbooks/dos-response.md](runbooks/dos-response.md) — if unexpected process or network activity is part of a resource-exhaustion or DoS attack.

Falco CRITICAL findings (`kube-policies shell in container`,
`kube-policies sensitive mount or privilege escalation`) map to **SEV1** per the IR
plan and trigger an immediate page to the incident commander.

## 7 Tuning (reducing false positives)

> References: NIST SI-4 (sensor tuning), SI-3 (malicious code detection),
> NIST SP 800-190 §4.4 (container runtime threats).

### 7.1 Allowlist expected processes

If a legitimate sidecar or init container triggers `kube-policies unexpected process
spawned`, add the process name to the `kube_policies_main_procs` macro in
`monitoring/falco/kube-policies-rules.yaml`:

```yaml
- macro: kube_policies_main_procs
  condition: (proc.name in (admission-webhook, policy-manager, dashboard, <your-proc>))
```

Then re-sync `deployments/kubernetes/runtime-detection/configmap.yaml` (copy the
updated rules content into the ConfigMap's `data` section).

### 7.2 Allowlist expected network destinations

If the SIEM endpoint uses a non-standard port (not 443, 6443, 8081, 8443, 53), add
it to the `kube-policies unexpected outbound connection` rule's `fd.rport` list:

```yaml
and not fd.rport in (443, 6443, 8081, 8443, 53, <your-siem-port>)
```

Always key on the **destination** (`fd.rport`/`fd.rip`), not the source port —
source-port allowlisting produces constant false positives and does not detect
exfiltration (P9 lessons learned).

### 7.3 Scope rules away from init containers

Falco applies rules to all containers including init containers. To exclude a
known-noisy init container from the `kube_policies_pods` macro:

```yaml
- macro: kube_policies_pods
  condition: >
    (k8s.ns.name = "kube-policies-system" or
     container.image.repository contains "kube-policies")
    and not container.name in (init-permissions, init-migrate)
```

### 7.4 Compliance references

| Standard | Control | Relevance |
|---|---|---|
| NIST SP 800-53 Rev 5 | SI-4 | Information System Monitoring — deploy sensors, collect indicators, alert on anomalies. |
| NIST SP 800-53 Rev 5 | SI-3 | Malicious Code Protection — detect and respond to malicious executables and shells at runtime. |
| NIST SP 800-53 Rev 5 | SI-4(2) | Automated Tools for Real-Time Analysis — Falco provides host-level syscall inspection independent of Kubernetes admission. |
| NIST SP 800-53 Rev 5 | SI-4(4) | Inbound and Outbound Communications Traffic — NetworkPolicy + Falco egress rules provide layered enforcement and detection. |
| NIST SP 800-53 Rev 5 | SC-7 | Boundary Protection — unexpected outbound connections from distroless pods are high-confidence exfiltration indicators. |
| NIST SP 800-190 | §4.4 | Container Runtime Threats — monitor for unexpected processes, filesystem modifications, and unusual network activity. |

## 8 Annual review

This document is reviewed at least **annually** (next review: **2027-06-01**) and whenever
the NetworkPolicy templates, Falco rules, or SIEM forwarding configuration changes.

## 9 References

- NetworkPolicy templates: `charts/kube-policies/templates/networkpolicy-*.yaml`
- Falco rules: `monitoring/falco/kube-policies-rules.yaml`
- SIEM integration: [docs/security/siem-integration.md](siem-integration.md)
- Continuous monitoring plan: [docs/security/continuous-monitoring-plan.md](continuous-monitoring-plan.md)
- On-call escalation: [docs/security/on-call-escalation.md](on-call-escalation.md)
- Incident response plan: [docs/security/incident-response-plan.md](incident-response-plan.md)
- POA&M: [docs/compliance/POAM.md](../compliance/POAM.md)
- NIST SP 800-53 Rev 5: SI-4, SI-4(2), SI-4(4), SC-7; CIS Kubernetes Benchmark 5.3.2; FedRAMP Moderate baseline.
