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

## 5 Annual review

This document is reviewed at least **annually** (next review: **2027-06-01**) and whenever
the NetworkPolicy templates, Falco rules, or SIEM forwarding configuration changes.

## 6 References

- NetworkPolicy templates: `charts/kube-policies/templates/networkpolicy-*.yaml`
- Falco rules: `monitoring/falco/kube-policies-rules.yaml`
- SIEM integration: [docs/security/siem-integration.md](siem-integration.md)
- Continuous monitoring plan: [docs/security/continuous-monitoring-plan.md](continuous-monitoring-plan.md)
- On-call escalation: [docs/security/on-call-escalation.md](on-call-escalation.md)
- Incident response plan: [docs/security/incident-response-plan.md](incident-response-plan.md)
- POA&M: [docs/compliance/POAM.md](../compliance/POAM.md)
- NIST SP 800-53 Rev 5: SI-4, SI-4(2), SI-4(4), SC-7; CIS Kubernetes Benchmark 5.3.2; FedRAMP Moderate baseline.
