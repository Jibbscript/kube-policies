# Cluster-Level Audit Policy (AUD-WU-16)

Controls: CIS Kubernetes Benchmark 3.2.1, 3.2.2, 1.2.x | NIST AU-2, AU-3, AU-12

---

## Overview

`deployments/kubernetes/cluster-audit/audit-policy.yaml` is the kube-apiserver
audit policy for the cluster. This is **distinct** from the admission webhook's
own audit log (`docs/audit/forwarding.md`):

| Audit layer | What it records | Where it lives |
|---|---|---|
| **kube-apiserver audit** (this doc) | Every API request to the cluster, including admission calls | Node filesystem, shipped by cluster-operator |
| **Webhook audit log** | Policy decisions made by kube-policies per admission request | `/var/log/kube-policies/audit.log` in the webhook pod |

The two layers are complementary. The kube-apiserver audit log captures the
`sourceIPs` of the originating caller and the full request context before
admission. The webhook audit log captures the policy decision, mutation patches,
and exception suppressions. They are correlated via the `requestID` / UID of
the `AdmissionRequest`.

### apiserver_id / source attribution

The admission webhook's `APIServerID` field (AUD-WU-01) is populated from the
HTTP `User-Agent` or a custom header supplied by the apiserver. If the apiserver
does not set a distinguishing header, this field will be empty. For authoritative
apiserver identity and originating client IP attribution, use the **apiserver
audit log** — the `AdmissionRequest` payload sent to the webhook does not carry
the originating client's IP.

---

## Required kube-apiserver flags

Apply these flags to every control-plane node's apiserver. For kubeadm-managed
clusters, edit `/etc/kubernetes/manifests/kube-apiserver.yaml`:

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    # Audit policy
    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
    # Log destination (adjust path to match your node's log layout)
    - --audit-log-path=/var/log/kubernetes/audit.log
    # Retention: NIST AU-11 / CIS 1.2.x — 90-day online minimum
    - --audit-log-maxage=90
    # Rotation
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100
```

Copy `deployments/kubernetes/cluster-audit/audit-policy.yaml` to
`/etc/kubernetes/audit-policy.yaml` on each control-plane node.

For managed Kubernetes services (EKS, GKE, AKS) the apiserver is not directly
accessible; use the provider's audit-log feature:

- **EKS**: enable CloudTrail and the EKS control-plane logging (API server,
  audit) in the cluster configuration.
- **GKE**: Cloud Audit Logs (Data Access logs) with the `container.googleapis.com`
  service.
- **AKS**: Azure Monitor diagnostic settings, `kube-apiserver` log category.

---

## Flag-to-control mapping

| Flag | CIS Benchmark | NIST control | Notes |
|---|---|---|---|
| `--audit-policy-file` | 1.2.22, 3.2.1 | AU-2, AU-12 | Must point at a non-empty policy |
| `--audit-log-path` | 1.2.22, 3.2.1 | AU-9 | Must not be `-` (stdout) in production |
| `--audit-log-maxage` | 1.2.23, 3.2.2 | AU-11 | 90 days minimum (FedRAMP-Moderate) |
| `--audit-log-maxbackup` | 1.2.24 | AU-4 | Keep at least 10 rotated files |
| `--audit-log-maxsize` | 1.2.25 | AU-4 | 100 MiB per file |

---

## Policy design

The policy is `audit.k8s.io/v1`, `kind: Policy`. Top-level `omitStages`
excludes `RequestReceived` (fires before auth; high-volume, low-value).
All other stages (`ResponseStarted`, `ResponseComplete`, `Panic`) are retained.

### Level selection rationale

| Resource category | Level | Rationale |
|---|---|---|
| Secrets (mutations) | `RequestResponse` | Full before/after for credential-access detection (AU-9, CIS 3.2.x) |
| Secrets (reads) | `Metadata` | Access pattern visible; body would expose secret values |
| ConfigMaps (mutations) | `RequestResponse` | Config drift detection (CM-3/CM-6) |
| kube-policies CRDs (`policies.kube-policies.io/*`) | `RequestResponse` | Policy changes are high-value (AC-3/AC-6) |
| RBAC (mutations) | `RequestResponse` | Privilege escalation detection (AC-2/AC-6, CIS 3.2.x) |
| ValidatingWebhookConfiguration, MutatingWebhookConfiguration | `RequestResponse` | Tampering disables admission controls silently (SC-7/SI-7) |
| NetworkPolicies | `RequestResponse` | Network segmentation changes (SC-7, CIS 5.3.x) |
| TokenReview / SubjectAccessReview | `RequestResponse` | Auth decisions (AC-2/IA-5) |
| CertificateSigningRequests | `RequestResponse` | Credential management (IA-5) |
| Namespaces (mutations) | `RequestResponse` | PSA label changes affect pod security admission (CIS 5.3.2) |
| Workloads (pods, deployments, etc.) — mutations | `Metadata` | Change detection without logging large pod specs |
| High-volume system components (kube-proxy, controller-manager, etc.) | `None` | Suppressed to control log volume (CIS 3.2.2) |
| Everything else | `Metadata` | AU-2 catch-all: sufficient detail to reconstruct events |

### CIS 3.2.1 — ensure audit logging is enabled

The policy file is non-empty and defines explicit rules covering all
security-relevant resource categories. `--audit-log-path` must be set to a
real file path (not `-`).

### CIS 3.2.2 — ensure audit policy is configured for key resources

The policy explicitly covers: secrets, configmaps, kube-policies CRDs, RBAC
resources, webhook configurations, network policies, token/access reviews, and
certificate signing requests — all at `RequestResponse` level for mutations.
Read-heavy non-security resources are logged at `Metadata` or `None` to control
volume.

---

## Correlation with webhook audit records

Each `PolicyDecision` record in the webhook audit log carries:

- `request_id` — the `AdmissionRequest.UID` (a UUID generated by the apiserver)
- `correlation_id` — defaults to `request_id` for admission events

The same UID appears in the apiserver audit log as `requestObject.uid` within
the `AdmissionReview` body logged for the webhook call. Use this UID to join
the two audit streams:

```bash
# Find the apiserver audit record for a webhook call
jq -r 'select(.objectRef.resource == "pods" and .verb == "create") | .requestObject' \
  /var/log/kubernetes/audit.log | jq -r '.request.uid'

# Match in webhook audit log
grep '"request_id":"<uid>"' /var/log/kube-policies/audit.log
```

---

## Limitations

- kube-policies is a pre-1.0 proof-of-concept; no ATO has been issued.
- The audit policy file is provided as a starting point. Operators must review
  it against their specific compliance requirements and resource inventory.
- The `--audit-log-maxage` flag controls age-based deletion of rotated files,
  not the retention of the current log. Pair with a log-shipping solution
  (`docs/audit/forwarding.md`) to meet the 90-day online-retention floor for
  FedRAMP-Moderate (AU-11).
- For managed Kubernetes services the apiserver flags are not directly settable;
  use the provider-native audit logging described above.
- No live-cluster validation of this policy has been performed against a
  real apiserver audit pipeline.

---

## References

- `deployments/kubernetes/cluster-audit/audit-policy.yaml` — the policy file
- CIS Kubernetes Benchmark v1.8, controls 1.2.22-1.2.25, 3.2.1-3.2.2
- NIST SP 800-53 Rev 5, AU-2, AU-3, AU-4, AU-11, AU-12
- Kubernetes documentation: [Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
