---
title: "CIS Kubernetes Benchmark v1.8 + NIST SP 800-190 — Self-Assessment Mapping"
doc_id: "DOC-WU-29"
status: "Active"
supersedes: "PROJECT_SUMMARY.md §Compliance Posture — prior 'Planned' statement for DOC-WU-29"
version: "1.0.0"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# CIS Kubernetes Benchmark v1.8 + NIST SP 800-190 — Self-Assessment Mapping

## Scope and honest status statement

This document is the **honest, per-control self-assessment** for the kube-policies
admission controller against two frameworks:

- **CIS Kubernetes Benchmark v1.8 — Section 5 (Policies)**
- **NIST SP 800-190 — Application Container Security Guide, Chapter 4 risk areas**

It **supersedes** the prior statement in `PROJECT_SUMMARY.md` that described this
crosswalk as "Planned — P10 / not yet authored". That statement is replaced by a
pointer to this document.

**What kube-policies is, and what it covers:**
kube-policies is a Kubernetes admission controller. Its enforcement surface is
strictly what passes through the Kubernetes API server admission webhook: pod
specs, RBAC objects, NetworkPolicies, Ingress objects, Secrets, and ConfigMaps
submitted at create/update time. The 30 bundled Rego rules (defined in
`internal/policy/control_matrix.yaml`) enforce CIS Section 5 (Policies) guardrails
across these object types.

**What kube-policies does NOT cover — by design:**
CIS Kubernetes Benchmark Sections 1–4 address control-plane configuration
(API server flags, controller-manager, scheduler, etcd, kubelet, and node OS
hardening). These are cluster-operator and cloud-provider responsibilities that an
admission controller cannot remediate. A row in Table 1 marked "Not-Covered" in the
CIS 1.x–4.x range is **not a gap in kube-policies** — it is correctly out of scope.
The existing `docs/compliance/cis-benchmark-results.md` document records the
control-plane ownership boundary in detail.

Status definitions used in this document:

| Status | Meaning |
|---|---|
| **Covered** | At least one shipped, enabled-by-default OR opt-in Rego rule in `control_matrix.yaml` directly implements the control at admission time |
| **Partial** | The admission rule exists but does not cover all sub-items (e.g. covers secrets-as-env but not encryption-at-rest), or coverage requires opt-in with no default enforcement |
| **Not-Covered** | No shipped rule covers this control; either out of admission-controller scope or a known gap (see POA&M) |

> **Coverage precondition — read before relying on any "Covered" row below.** A
> rule only enforces a control for objects the admission webhook actually
> intercepts. The shipped Helm chart and kustomize base register the webhook for
> **`pods` only**. Therefore every "Covered" row whose rule targets a **non-pod
> kind** — RBAC (5.1.x → `*roles`/`*bindings`), NetworkPolicy/Ingress (5.3.x),
> Secret/ConfigMap (5.4.x) — and any rule meant to evaluate a **workload
> controller at apply time** requires the operator to BOTH (1) select the opt-in
> profile AND (2) widen `admissionWebhook.webhook.rules` to that kind. Until the
> webhook is widened those rules never receive their target objects and the
> control is **not enforced in the default configuration**. Pod-targeted rules
> (5.2.x) are enforced once their profile is enabled, because Pods are
> intercepted by default. This webhook-widening requirement is tracked as
> **POAM-POL-013**. See `docs/policy-profiles.md` → "Webhook coverage".

---

## Table 1 — CIS Kubernetes Benchmark v1.8, Section 5 (Policies)

> Sections 1–4 (control-plane, etcd, node config) are **out of scope for an
> admission controller**. They are listed once as a group for completeness, then
> Section 5 is mapped control-by-control.

### CIS Sections 1–4: Control-Plane, etcd, Node (Out of Scope)

| CIS Section | Description | Status | Rule | Notes |
|---|---|---|---|---|
| 1.1.x | API server configuration files (permissions, ownership) | Not-Covered | — | Node/operator responsibility; kube-policies has no admission hook into node filesystem config |
| 1.2.x | API server flags (anonymous-auth, TLS, RBAC mode, audit) | Not-Covered | — | Control-plane/operator responsibility; out of admission-controller boundary |
| 1.3.x | Controller-manager flags | Not-Covered | — | Control-plane/operator responsibility |
| 1.4.x | Scheduler flags | Not-Covered | — | Control-plane/operator responsibility |
| 2.x | etcd security (TLS, access control) | Not-Covered | — | Control-plane/operator responsibility |
| 3.x | Control-plane config (audit policy, encryption provider) | Not-Covered | — | Cluster-operator responsibility; encryption-at-rest sample in `deployments/kubernetes/encryption/` |
| 4.1.x | Worker node config file permissions | Not-Covered | — | Node/operator responsibility |
| 4.2.x | Kubelet configuration flags | Not-Covered | — | Node/operator responsibility; see `cis-benchmark-results.md` §4.2.x |

### CIS 5.1 — RBAC and Service Accounts

| CIS ID | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 5.1.1 | Ensure cluster-admin role is used only where required | **Covered** | `deny-cluster-admin-binding`, `deny-dangerous-verbs`, `deny-broad-subject-binding` | Bindings referencing cluster-admin are denied at admission; dangerous verbs (escalate/bind/impersonate) are blocked; broad subjects (system:authenticated etc.) are blocked |
| 5.1.2 | Minimize access to secrets | **Covered** | `deny-cluster-admin-binding` | cluster-admin grants are blocked; wholesale Secrets access via wildcard would be caught by `deny-wildcard-rbac` |
| 5.1.3 | Minimize wildcard use in Roles and ClusterRoles | **Covered** | `deny-wildcard-rbac` | Wildcard verbs, resources, or apiGroups in any rule are denied at admission |
| 5.1.4 | Minimize access to create pods | **Partial** | `deny-dangerous-verbs` | The rule blocks escalate/bind/impersonate; a specific deny on `create pods` verb is not implemented — only indirect coverage via wildcard block |
| 5.1.5 | Ensure default service accounts are not bound to cluster roles | **Partial** | `require-automount-token-disabled` | Token automount is denied; binding default SA to cluster roles is not explicitly checked — depends on `deny-cluster-admin-binding` catching the role reference |
| 5.1.6 | Ensure service account tokens are not automatically mounted | **Covered** | `require-automount-token-disabled` | `automountServiceAccountToken` must be explicitly false unless an annotation opt-in is present; opt-in policy `nsa-hardening` |

### CIS 5.2 — Pod Security Standards

| CIS ID | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 5.2.1 | Ensure that the cluster has at least one active policy control mechanism in place | **Covered** | (engine itself) | kube-policies IS the admission policy enforcement mechanism; PSA labels also enforced by `governance-baseline` profile |
| 5.2.2 | Minimize the admission of privileged containers | **Covered** | `no-privileged-containers` | Default-on; `privileged: true` is denied |
| 5.2.3 | Minimize the admission of containers wishing to share the host process ID namespace | **Covered** | `deny-host-namespaces` | `hostPID: true` denied; opt-in `pss-baseline` policy |
| 5.2.4 | Minimize the admission of containers wishing to share the host IPC namespace | **Covered** | `deny-host-namespaces`, `deny-host-port`, `restrict-volume-types` | `hostIPC: true` denied; hostPort denied; volume types restricted |
| 5.2.5 | Minimize the admission of containers with allowPrivilegeEscalation | **Covered** | `require-no-privilege-escalation`, `deny-host-namespaces` | `allowPrivilegeEscalation` must be explicitly false; opt-in `pss-restricted` policy |
| 5.2.6 | Minimize the admission of root containers | **Covered** | `required-security-context`, `require-run-as-nonroot` | Default-on `required-security-context` checks for security context presence; `require-run-as-nonroot` enforces `runAsNonRoot=true` and blocks `runAsUser=0` |
| 5.2.7 | Minimize the admission of containers with added capability | **Covered** | `seccomp-not-unconfined`, `deny-unsafe-sysctls`, `deny-apparmor-unconfined` | Unconfined seccomp/AppArmor blocked; unsafe sysctls blocked; opt-in `pss-baseline` |
| 5.2.8 | Minimize the admission of containers with added capabilities | **Covered** | `restrict-capabilities` | Only NET_BIND_SERVICE is allowed; all other `add` capabilities denied |
| 5.2.9 | Minimize the admission of containers with capabilities assigned | **Covered** | `restrict-capabilities`, `require-drop-all-capabilities` | `restrict-capabilities` blocks disallowed adds; `require-drop-all-capabilities` requires `drop: [ALL]` |
| 5.2.10 | Minimize the admission of Windows HostProcess containers | **Not-Covered** | — | No Rego rule targets Windows `hostProcess` security context; Windows workloads are not in scope for the current PSS rule set (POAM-POL-001) |
| 5.2.11 | Minimize the admission of HostPath volumes | **Covered** | `no-host-path-volumes` | Default-on; `hostPath` volumes are denied |
| 5.2.12 | Minimize the admission of containers that run with a root primary or supplementary GID | **Partial** | `require-run-as-nonroot` | `runAsUser=0` and missing `runAsNonRoot` are blocked; `runAsGroup=0` and `supplementalGroups` containing 0 are not explicitly checked (POAM-POL-002) |
| 5.2.13 | Ensure that the seccomp profile is set to docker/default or runtime/default | **Partial** | `seccomp-not-unconfined` | Unconfined seccomp is blocked; the rule does not REQUIRE RuntimeDefault to be affirmatively set (only rejects Unconfined) — the mutating `harden-pod-securitycontext` rule defaults it to RuntimeDefault on mutation (POAM-POL-003) |

### CIS 5.3 — Network Policies and CNI

| CIS ID | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 5.3.1 | Ensure that the CNI in use supports Network Policies | **Not-Covered** | — | CNI selection is a cluster-operator responsibility; admission controller cannot enforce CNI capability |
| 5.3.2 | Ensure that all Namespaces have Network Policies defined | **Partial** | `deny-overly-broad-netpol` | Overly broad NetworkPolicies (empty podSelector + allow-all ingress) are denied; the rule does not REQUIRE a NetworkPolicy to be present in every namespace — that is a posture check owned by conftest `network.posture` gate (POAM-POL-004) |
| 5.3.3 | Ensure that Ingress objects require TLS and do not use wildcard hosts | **Covered** | `ingress-require-tls-no-wildcard` | Ingress objects without TLS or with wildcard hosts are denied; opt-in `network-baseline` policy |

### CIS 5.4 — Secrets Management

| CIS ID | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 5.4.1 | Prefer using Secrets as files over Secrets as environment variables | **Covered** | `deny-secret-env`, `flag-configmap-sensitive` | Secrets consumed via `valueFrom.secretKeyRef` or `envFrom.secretRef` are denied; ConfigMap keys matching credential patterns are flagged; opt-in `secrets-baseline` policy |
| 5.4.2 | Consider external secret management systems | **Not-Covered** | — | External secret manager integration is a cluster/application architect decision; not enforceable by admission controller (POAM-POL-005) |

### CIS 5.5 — Extensible Admission Control

| CIS ID | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 5.5.1 | Configure Image Provenance using ImagePolicyWebhook or ImagePolicyAdmission | **Covered** | `allowed-registries`, `require-image-digest` | Registry allowlist and image-by-digest enforcement are admission-time rules; opt-in `image-provenance` policy |

### CIS 5.7 — General Policies

| CIS ID | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 5.7.1 | Create administrative boundaries between resources using namespaces | **Covered** | `deny-default-namespace`, `require-labels` | Workloads in the default namespace are denied; mandatory ownership/classification labels enforced; opt-in `governance-baseline` policy |
| 5.7.2 | Ensure that the seccomp profile is set to docker/default or runtime/default | **Partial** | `seccomp-not-unconfined` | See note for 5.2.13 — same rule; blocks Unconfined but does not require affirmative RuntimeDefault on validate-only path (POAM-POL-003) |
| 5.7.3 | Apply Security Context to your Pods and Containers | **Covered** | `require-resource-limits`, `required-security-context` | Resource limits required; security context required; `require-resource-limits` is opt-in `nsa-hardening` |
| 5.7.4 | The default namespace should not be used | **Covered** | `deny-default-namespace` | Workloads in `default` namespace are denied at admission; opt-in `governance-baseline` policy |

---

## Table 2 — NIST SP 800-190 Container Risk Areas (Chapter 4)

> 800-190 Chapter 4 defines five risk areas. Coverage is assessed against the
> admission-time enforcement surface of kube-policies. Controls that require
> build-time, registry-side, or runtime tooling outside the admission webhook are
> noted accordingly.

### 4.1 — Image Risks

| 800-190 Risk | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 4.1.1 | Image vulnerabilities (use of vulnerable images) | **Partial** | `allowed-registries`, `require-image-digest` | Registry allowlist prevents images from untrusted sources; digest pinning prevents tag drift; however actual vulnerability scanning (CVE checking) is a build/registry-side control, not enforceable at admission time without an external scan result attestation (POAM-POL-006) |
| 4.1.2 | Image configuration defects (e.g. :latest tag) | **Covered** | `no-latest-image-tag` | Default-on; images with `:latest` tag are denied |
| 4.1.3 | Embedded malware | **Not-Covered** | — | Malware detection requires image scanning at build/registry time; not an admission-time control (POAM-POL-007) |
| 4.1.4 | Embedded clear-text secrets | **Partial** | `flag-configmap-sensitive`, `deny-secret-env` | Secrets-as-env and sensitive ConfigMap keys are caught at admission; secrets baked into image layers cannot be inspected by an admission webhook (POAM-POL-008) |
| 4.1.5 | Use of untrusted images | **Covered** | `allowed-registries`, `require-image-digest` | Registry allowlist and digest pinning together enforce image provenance; opt-in `image-provenance` policy |

### 4.2 — Registry Risks

| 800-190 Risk | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 4.2.1 | Insecure connections to registries | **Not-Covered** | — | Registry transport security is a cluster infrastructure concern (containerd/CRI config); not enforceable at admission time |
| 4.2.2 | Stale images in registry | **Not-Covered** | — | Registry lifecycle management is an operational process; not enforceable at admission time |
| 4.2.3 | Insufficient authentication/authorization to registry | **Not-Covered** | — | Registry access control is a registry/operator responsibility |
| 4.2.4 | Vulnerabilities in registry software | **Not-Covered** | — | Registry infrastructure security is an operator responsibility |

### 4.3 — Orchestrator Risks

| 800-190 Risk | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 4.3.1 | Unbounded administrative access | **Covered** | `deny-wildcard-rbac`, `deny-dangerous-verbs`, `deny-cluster-admin-binding`, `deny-broad-subject-binding` | Wildcard RBAC, dangerous verbs, cluster-admin bindings, and broad-subject bindings are all denied at admission; opt-in `rbac-baseline` policy |
| 4.3.2 | Unauthorized access to workloads / network segmentation | **Partial** | `deny-overly-broad-netpol`, `ingress-require-tls-no-wildcard` | Overly broad NetworkPolicies and unsafe Ingress are denied; namespace-wide default-deny presence is a posture check, not an admission enforcement (POAM-POL-004) |
| 4.3.3 | Poorly configured resource quotas | **Covered** | `require-resource-limits` | CPU and memory requests/limits required on every container; opt-in `nsa-hardening` policy |
| 4.3.4 | Container breakout via host namespace access | **Covered** | `deny-host-namespaces`, `no-host-path-volumes`, `deny-host-port`, `restrict-volume-types` | Host PID/IPC/network namespaces denied; hostPath volumes denied (default-on); hostPort denied; volume types restricted to PSS-Restricted allowlist |
| 4.3.5 | Lack of container logging | **Not-Covered** | — | Log configuration is an application and cluster infrastructure concern; not enforceable via admission webhook on pod specs (POAM-POL-009) |

### 4.4 — Container Risks

| 800-190 Risk | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 4.4.1 | Vulnerable container runtimes | **Not-Covered** | — | Container runtime patching is a node/operator responsibility |
| 4.4.2 | Containers running as root or with excessive privilege | **Covered** | `no-privileged-containers`, `required-security-context`, `require-run-as-nonroot`, `require-no-privilege-escalation`, `restrict-capabilities`, `require-drop-all-capabilities`, `harden-pod-securitycontext` | Privileged containers, root users, privilege escalation, and excessive capabilities are all denied; mutating rule auto-defaults missing hardening fields |
| 4.4.3 | Container images with setuid/setgid binaries | **Not-Covered** | — | Binary permission scanning requires image layer inspection at build time; not visible to admission webhook (POAM-POL-010) |
| 4.4.4 | Inappropriate inter-container trust | **Covered** | `seccomp-not-unconfined`, `deny-unsafe-sysctls`, `deny-apparmor-unconfined` | Unconfined seccomp, unsafe sysctls, and unconfined AppArmor all blocked; limits kernel attack surface between containers |
| 4.4.5 | Host OS vulnerabilities exploited by containers | **Partial** | `no-host-path-volumes`, `deny-host-namespaces` | Host filesystem and namespace isolation enforced; kernel-level patching is a node/operator responsibility (POAM-POL-011) |

### 4.5 — Secrets Risks

| 800-190 Risk | Description | Status | Implementing Rule | Notes |
|---|---|---|---|---|
| 4.5.1 | Secrets stored in images | **Partial** | `flag-configmap-sensitive` | Plaintext credentials in ConfigMap keys are caught; secrets baked into image layers are not inspectable at admission time (POAM-POL-008) |
| 4.5.2 | Secrets stored in environment variables | **Covered** | `deny-secret-env` | Secrets consumed via env `valueFrom.secretKeyRef` or `envFrom.secretRef` are denied; opt-in `secrets-baseline` policy |
| 4.5.3 | Encryption of secrets at rest | **Not-Covered** | — | Kubernetes-level encryption-at-rest (EncryptionConfiguration) is a control-plane/operator responsibility; a sample `deployments/kubernetes/encryption/` document is provided but kube-policies does not enforce encryption-at-rest (POAM-POL-012) |

---

## Coverage summary

### CIS Kubernetes Benchmark v1.8 — Section 5

| Status | Count | Control IDs |
|---|---|---|
| **Covered** | 20 | 5.1.1, 5.1.2, 5.1.3, 5.1.6, 5.2.1, 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 5.2.7, 5.2.8, 5.2.9, 5.2.11, 5.3.3, 5.4.1, 5.5.1, 5.7.1, 5.7.3, 5.7.4 |
| **Partial** | 6 | 5.1.4, 5.1.5, 5.2.12, 5.2.13, 5.3.2, 5.7.2 |
| **Not-Covered** | 5 | 5.2.10, 5.3.1, 5.4.2, and CIS Sections 1–4 (all out of admission-controller scope) |

> Note: 5.7.1 and 5.7.4 both map to `deny-default-namespace`; 5.7.3 maps to two
> rules. The count above reflects unique Section 5 leaf controls assessed.

### NIST SP 800-190 Chapter 4

| Status | Count | Risk Areas |
|---|---|---|
| **Covered** | 7 | 4.1.2, 4.1.5, 4.3.1, 4.3.3, 4.3.4, 4.4.2, 4.4.4, 4.5.2 |
| **Partial** | 5 | 4.1.1, 4.1.4, 4.3.2, 4.4.5, 4.5.1 |
| **Not-Covered** | 9 | 4.1.3, 4.2.1–4.2.4, 4.3.5, 4.4.1, 4.4.3, 4.5.3 |

> The majority of Not-Covered items (registry risks 4.2.x, image malware 4.1.3,
> runtime patching 4.4.1) are correctly out of scope for an admission controller.
> Build/registry/runtime tooling is the right remediation layer for those risks.

---

## POA&M entries

The following items are open weaknesses or accepted out-of-scope decisions arising
from this self-assessment. Each is a discrete POA&M line. Out-of-scope items are
accepted as architectural boundary decisions; gaps are tracked for remediation.

| POA&M ID | Framework Ref | Gap Description | Planned Remediation / Disposition |
|---|---|---|---|
| POAM-POL-001 | CIS 5.2.10 | No rule checks Windows HostProcess containers (`securityContext.windowsOptions.hostProcess`) | Accepted: Windows workloads are out of scope for the current rule set. Add rule if Windows node support is added. |
| POAM-POL-002 | CIS 5.2.12 | `runAsGroup=0` and `supplementalGroups` containing 0 are not explicitly checked; only `runAsUser=0` and `runAsNonRoot` are enforced | Planned: add `deny-root-gid` rule to `pss-restricted` policy pack (future phase) |
| POAM-POL-003 | CIS 5.2.13, 5.7.2 | Validating path blocks Unconfined seccomp but does not REQUIRE `RuntimeDefault` to be affirmatively set; only the mutating `harden-pod-securitycontext` rule defaults it | Planned: add a validating rule that requires `seccompProfile.type` to be `RuntimeDefault` or `Localhost` on the `pss-restricted` profile (future phase) |
| POAM-POL-004 | CIS 5.3.2, 800-190 4.3.2 | No admission rule REQUIRES a NetworkPolicy to be present in every namespace; the conftest `network.posture` gate catches this for the kube-policies own namespace but not cluster-wide | Planned: cluster-wide namespace posture check is a cluster-operator responsibility; consider adding an audit-mode rule for namespace-level NetworkPolicy presence (future phase) |
| POAM-POL-005 | CIS 5.4.2 | No rule enforces use of an external secret manager (Vault, AWS Secrets Manager, etc.) | Accepted: external secret manager selection is an architectural decision; not enforceable generically at admission time |
| POAM-POL-006 | 800-190 4.1.1 | CVE / vulnerability scan results are not checked at admission time | Planned: admission-time image vulnerability attestation check (requires external scanner with DSSE/cosign attestation support) — future phase |
| POAM-POL-007 | 800-190 4.1.3 | Embedded malware in images is not detectable at admission time | Accepted: malware detection requires build/registry-side scanning; out of admission-controller scope by design |
| POAM-POL-008 | 800-190 4.1.4, 4.5.1 | Secrets baked into image layers are not inspectable by the admission webhook | Accepted: image layer inspection requires build-time scanning; `flag-configmap-sensitive` + `deny-secret-env` address what IS inspectable at admission time |
| POAM-POL-009 | 800-190 4.3.5 | No rule enforces log driver configuration on container specs | Accepted: log configuration is an application and infrastructure concern; enforcing a specific log driver at admission time is not practical across all workload types |
| POAM-POL-010 | 800-190 4.4.3 | setuid/setgid binaries in image layers are not detectable at admission time | Accepted: binary permission scanning requires image layer inspection at build time; out of admission-controller scope |
| POAM-POL-011 | 800-190 4.4.5 | Kernel-level OS patching is not enforceable by an admission controller | Accepted: node OS patching is a cluster-operator / cloud-provider responsibility |
| POAM-POL-012 | 800-190 4.5.3 | Kubernetes-level encryption-at-rest (`EncryptionConfiguration`) is not enforced by kube-policies | Accepted: EncryptionConfiguration is a control-plane/operator responsibility; sample configuration provided in `deployments/kubernetes/encryption/` as operator guidance |
| POAM-POL-013 | CIS 5.1.x, 5.3.x, 5.4.x | The shipped Helm chart/kustomize webhook intercepts `pods` only, so the RBAC, NetworkPolicy/Ingress, and Secret/ConfigMap rule packs — and workload-controller-at-apply-time evaluation — are inert until the operator widens `admissionWebhook.webhook.rules` to those kinds. Pod-targeted controls (5.2.x) are enforced by default once their profile is enabled. | Planned: ship per-pack webhook-coverage values (gated, off by default to bound the fail-closed blast radius) so selecting the `cis`/`nsa` profile can opt into the matching webhook rules; until then, widening is a documented operator step (`docs/policy-profiles.md` → "Webhook coverage"). |
