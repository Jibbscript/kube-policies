# Policy Library (POL-WU-29)

The kube-policies engine ships 30 bundled rules organized into 10 policy packs. All packs except `security-baseline` are **opt-in** — they are disabled by default and activated only when you select an enforcement profile (see [Policy Profiles](policy-profiles.md)).

## Architecture & Concepts

### Shared Library (POL-WU-01)

Every rule is compiled alongside the shared pod-spec library (`data.kube_policies.lib` from `internal/policy/rego/podspec.rego`). This library extracts the **effective pod spec** across:

- Workload controllers (Pod, Deployment, ReplicaSet, DaemonSet, StatefulSet, Job, CronJob, ReplicationController)
- InitContainers and ephemeralContainers

This means a rule like `require-drop-all-capabilities` evaluates every container in the workload, not just the primary containers.

### Kind Routing (POL-WU-21)

Each rule declares target Kubernetes kinds (`TargetKinds`). This prevents:

- Pod-shaped rules from firing on RBAC objects (Role, ClusterRole, RoleBinding, ClusterRoleBinding)
- RBAC rules from evaluating Pod specs
- All rules coexist safely in one admission webhook

Pod rules target: Pod, Deployment, ReplicaSet, DaemonSet, StatefulSet, Job, CronJob, ReplicationController.

### Webhook Coverage (Important)

Kind routing governs what the *engine* evaluates; what the engine *receives* is
set by the admission webhook registration. The shipped Helm chart and kustomize
base register the webhook for **`pods` only**. So:

- **Pod-targeted packs** (`security-baseline`, `pss-baseline`, `pss-restricted`,
  `nsa-hardening`, `governance-baseline`, `mutating-hardening`) enforce once their
  profile is enabled — Pods are intercepted by default, including the Pods that
  workload controllers create (the shared library traverses init/ephemeral
  containers on them).
- **Non-pod packs** (`rbac-baseline`, `secrets-baseline`, `network-baseline`) and
  **workload-controller-at-apply-time** evaluation require the operator to widen
  `admissionWebhook.webhook.rules` to those kinds. Until then these rules never
  receive their target objects. Tracked as **POAM-POL-013**; see
  [Policy Profiles → Webhook coverage](policy-profiles.md) and the
  [CIS/800-190 mapping](compliance/cis-k8s-800-190-mapping.md).

### Exceptions (PolicyException CRs)

Operators can suppress rule violations on a per-namespace, per-resource, or per-user basis using `PolicyException` custom resources. See [examples/policies/security-baseline.yaml](../examples/policies/security-baseline.yaml) for the exception format and `spec.exceptions:` block example.

---

## Security Baseline (Default-On)

The `security-baseline` policy ships **enabled by default** and includes 4 foundational rules covering the most dangerous pod misconfigurations.

### no-privileged-containers

**Policy:** security-baseline | **Severity:** HIGH | **Controls:** CIS 5.2.2, PSS Baseline: Privileged Containers, NIST SP 800-190 4.4.2, NIST AC-6

**Included in:** All enforcement profiles (pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis)

**Description:** Containers must not run in privileged mode.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      privileged: true
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      privileged: false
      runAsNonRoot: true
      allowPrivilegeEscalation: false
```

---

### no-host-path-volumes

**Policy:** security-baseline | **Severity:** HIGH | **Controls:** CIS 5.2.12, PSS Baseline: HostPath Volumes, NIST SP 800-190 4.3.4, NIST CM-7

**Included in:** All enforcement profiles (pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis)

**Description:** HostPath volumes are not allowed.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    volumeMounts:
    - name: host-data
      mountPath: /data
  volumes:
  - name: host-data
    hostPath:
      path: /var/lib/important
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    emptyDir: {}
```

---

### no-latest-image-tag

**Policy:** security-baseline | **Severity:** MEDIUM | **Controls:** CIS 5.7.4, NIST SP 800-190 4.1.2, NIST CM-2

**Included in:** All enforcement profiles (pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis)

**Description:** Container images must not use `:latest` or an implicit latest tag.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:latest
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

---

### required-security-context

**Policy:** security-baseline | **Severity:** MEDIUM | **Controls:** CIS 5.2.6, PSS Restricted: Running as Non-root, NIST SP 800-190 4.4.2, NIST AC-6

**Included in:** All enforcement profiles (pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis)

**Description:** Containers must declare a securityContext that runs as non-root and disallows privilege escalation.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
```

---

## Image Provenance (Opt-In)

The `image-provenance` policy is **disabled by default** (no default enforcement). Enable it via the `nsa` or custom profiles.

### allowed-registries

**Policy:** image-provenance | **Severity:** HIGH | **Controls:** NSA Hardening: Supply Chain, NIST SP 800-190 4.1.1, NIST CM-7, NIST SR-3

**Included in:** nsa, cis (custom profile only)

**Description:** Container images must come from an allowlisted registry. The default allowlist is `ghcr.io/jibbscript/`; operators override it via `Policy.spec.parameters.allowedRegistries`.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: docker.io/library/ubuntu:20.04@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: ghcr.io/jibbscript/myapp:v1.0.0@sha256:abcd1234
```

---

### require-image-digest

**Policy:** image-provenance | **Severity:** HIGH | **Controls:** NSA Hardening: Supply Chain, NIST SP 800-190 4.1.1, SLSA L2, NIST SR-4

**Included in:** nsa, cis (custom profile only)

**Description:** Container images must be pinned by immutable digest (@sha256:...) for verifiable provenance.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: ghcr.io/jibbscript/myapp:v1.0.0
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: ghcr.io/jibbscript/myapp:v1.0.0@sha256:abcd1234567890
```

---

## PSS Baseline (Opt-In)

The `pss-baseline` policy bundles 6 rules implementing Pod Security Standards "baseline" controls. Enable via the `pss-baseline`, `pss-restricted`, `pss-restricted-mutating`, or `cis` profiles.

### deny-host-namespaces

**Policy:** pss-baseline | **Severity:** HIGH | **Controls:** CIS 5.2.3, CIS 5.2.4, CIS 5.2.5, PSS Baseline: Host Namespaces, NIST SP 800-190 4.3.4

**Included in:** pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Pods must not share the host network, PID, or IPC namespaces.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

---

### restrict-capabilities

**Policy:** pss-baseline | **Severity:** HIGH | **Controls:** CIS 5.2.8, CIS 5.2.9, PSS Baseline: Capabilities, NIST SP 800-190 4.4.2, NIST AC-6

**Included in:** pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Containers may only add NET_BIND_SERVICE; NET_RAW, SYS_ADMIN and other capabilities are denied.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      capabilities:
        add:
        - NET_RAW
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      capabilities:
        add:
        - NET_BIND_SERVICE
```

---

### deny-host-port

**Policy:** pss-baseline | **Severity:** MEDIUM | **Controls:** CIS 5.2.4, PSS Baseline: HostPorts, NSA Hardening: Pod

**Included in:** pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Containers must not bind a hostPort.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    ports:
    - containerPort: 8080
      hostPort: 8080
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    ports:
    - containerPort: 8080
```

---

### seccomp-not-unconfined

**Policy:** pss-baseline | **Severity:** HIGH | **Controls:** CIS 5.2.7, PSS Baseline: Seccomp, NIST SP 800-190 4.4.4

**Included in:** pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Pod and container seccompProfile.type must not be Unconfined.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  securityContext:
    seccompProfile:
      type: Unconfined
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

---

### deny-unsafe-sysctls

**Policy:** pss-baseline | **Severity:** MEDIUM | **Controls:** CIS 5.2.7, PSS Baseline: Sysctls, NIST SP 800-190 4.4.4

**Included in:** pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Pods may only set the PSS-Baseline safe sysctls (kernel.shm_rmid_forced, net.ipv4.ip_local_port_range, net.ipv4.ip_unprivileged_port_start, net.ipv4.tcp_syncookies, net.ipv4.ping_group_range, net.ipv4.ip_local_reserved_ports).

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  securityContext:
    sysctls:
    - name: net.core.somaxconn
      value: "65536"
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  securityContext:
    sysctls:
    - name: net.ipv4.tcp_syncookies
      value: "1"
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

---

### deny-apparmor-unconfined

**Policy:** pss-baseline | **Severity:** HIGH | **Controls:** CIS 5.2.7, PSS Baseline: AppArmor, NIST SP 800-190 4.4.4

**Included in:** pss-baseline, pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Containers must not disable AppArmor (appArmorProfile.type=Unconfined or the legacy unconfined annotation).

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: "unconfined"
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: "runtime/default"
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

---

## PSS Restricted (Opt-In)

The `pss-restricted` policy bundles 5 rules implementing Pod Security Standards "restricted" controls on top of baseline. Enable via the `pss-restricted`, `pss-restricted-mutating`, or `cis` profiles.

### require-no-privilege-escalation

**Policy:** pss-restricted | **Severity:** HIGH | **Controls:** CIS 5.2.5, PSS Restricted: Privilege Escalation, NIST SP 800-190 4.4.2, NIST AC-6

**Included in:** pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Every container must set securityContext.allowPrivilegeEscalation=false.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      allowPrivilegeEscalation: true
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      allowPrivilegeEscalation: false
```

---

### require-drop-all-capabilities

**Policy:** pss-restricted | **Severity:** HIGH | **Controls:** CIS 5.2.9, PSS Restricted: Capabilities, NIST SP 800-190 4.4.2, NIST AC-6

**Included in:** pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Every container must drop ALL capabilities.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      capabilities:
        drop:
        - NET_RAW
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      capabilities:
        drop:
        - ALL
```

---

### require-readonly-rootfs

**Policy:** pss-restricted | **Severity:** MEDIUM | **Controls:** PSS Restricted: Read-only Root Filesystem, NSA Hardening: Pod, NIST SP 800-190 4.4.1, NIST CM-7

**Included in:** pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Every container must set securityContext.readOnlyRootFilesystem=true.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      readOnlyRootFilesystem: false
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
```

---

### require-run-as-nonroot

**Policy:** pss-restricted | **Severity:** HIGH | **Controls:** CIS 5.2.6, PSS Restricted: Running as Non-root, NIST SP 800-190 4.4.2, NIST AC-6

**Included in:** pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Pods must run as non-root (runAsNonRoot at pod or every container) and must not set runAsUser=0.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      runAsUser: 0
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

---

### restrict-volume-types

**Policy:** pss-restricted | **Severity:** MEDIUM | **Controls:** CIS 5.2.4, PSS Restricted: Volume Types, NIST SP 800-190 4.3.4

**Included in:** pss-restricted, pss-restricted-mutating, nsa, cis

**Description:** Pod volumes must use only the PSS-Restricted allowed volume types (configMap, csi, downwardAPI, emptyDir, ephemeral, persistentVolumeClaim, projected, secret).

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
  volumes:
  - name: host-vol
    hostPath:
      path: /var/lib/data
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
  volumes:
  - name: data
    emptyDir: {}
  - name: config
    configMap:
      name: app-config
```

---

## NSA Hardening (Opt-In)

The `nsa-hardening` policy bundles 2 rules implementing NSA/CISA and NIST SP 800-190 hardening controls not covered by PSS packs. Enable via the `nsa` or `cis` profiles.

### require-resource-limits

**Policy:** nsa-hardening | **Severity:** MEDIUM | **Controls:** CIS 5.7.3, NSA Hardening: Resource Limits, NIST SP 800-190 4.3.3, NIST SC-6

**Included in:** nsa, cis

**Description:** Every container must set CPU and memory requests and limits.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 500m
        memory: 512Mi
```

---

### require-automount-token-disabled

**Policy:** nsa-hardening | **Severity:** MEDIUM | **Controls:** CIS 5.1.5, CIS 5.1.6, NSA Hardening: RBAC, NIST SP 800-190 4.2.4, NIST AC-6

**Included in:** nsa, cis

**Description:** automountServiceAccountToken must be explicitly false unless the workload opts in via the `policy.kube-policies.io/allow-automount-token` annotation.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  automountServiceAccountToken: false
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

---

## Governance Baseline (Opt-In)

The `governance-baseline` policy bundles 2 rules implementing FedRAMP inventory and namespace-isolation governance controls. Enable via the `cis` profile (requires custom profile for standalone use).

### require-labels

**Policy:** governance-baseline | **Severity:** LOW | **Controls:** CIS 5.7.1, NIST CM-8, NIST CM-8(1), NIST SP 800-190 4.3.1

**Included in:** cis

**Description:** Workloads must carry the mandatory inventory labels. The default set is `app.kubernetes.io/name,owner,data-classification`; operators override via `Policy.spec.parameters.requiredLabels`.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  labels:
    app: myapp
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  labels:
    app.kubernetes.io/name: myapp
    owner: platform-team
    data-classification: public
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

---

### deny-default-namespace

**Policy:** governance-baseline | **Severity:** LOW | **Controls:** CIS 5.7.1, NSA Hardening: Namespaces, NIST SP 800-190 4.3.1, NIST CM-8

**Included in:** cis

**Description:** Workloads must not be created in the default namespace.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: default
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: kube-policies-system
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

---

## RBAC Baseline (Opt-In)

The `rbac-baseline` policy bundles 4 rules implementing CIS 5.1 RBAC least-privilege controls. These rules read RBAC objects (Role, ClusterRole, RoleBinding, ClusterRoleBinding), not pod specs. Enable via the `cis` profile.

### deny-wildcard-rbac

**Policy:** rbac-baseline | **Severity:** HIGH | **Controls:** CIS 5.1.3, NSA Hardening: RBAC, NIST SP 800-190 4.2.4, NIST AC-6, NIST AC-6(1)

**Included in:** cis

**Description:** Roles/ClusterRoles must not grant wildcard verbs, resources, or apiGroups.

**Denied manifest:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

**Allowed manifest:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: good-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

---

### deny-dangerous-verbs

**Policy:** rbac-baseline | **Severity:** HIGH | **Controls:** CIS 5.1.1, CIS 5.1.4, NSA Hardening: RBAC, NIST AC-6, NIST AC-6(1)

**Included in:** cis

**Description:** Roles/ClusterRoles must not grant escalate, bind, or impersonate.

**Denied manifest:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bad-role
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["escalate"]
```

**Allowed manifest:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: good-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

---

### deny-cluster-admin-binding

**Policy:** rbac-baseline | **Severity:** HIGH | **Controls:** CIS 5.1.1, CIS 5.1.2, NSA Hardening: RBAC, NIST AC-6, NIST AC-3

**Included in:** cis

**Description:** Bindings must not reference the built-in cluster-admin ClusterRole.

**Denied manifest:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: developer@example.com
```

**Allowed manifest:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: good-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
- kind: User
  name: developer@example.com
```

---

### deny-broad-subject-binding

**Policy:** rbac-baseline | **Severity:** HIGH | **Controls:** CIS 5.1.1, CIS 5.1.6, NSA Hardening: RBAC, NIST AC-6, NIST AC-6(1)

**Included in:** cis

**Description:** Bindings must not grant permissions to system:authenticated, system:unauthenticated, or system:anonymous.

**Denied manifest:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
- kind: Group
  name: system:authenticated
```

**Allowed manifest:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: good-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
- kind: ServiceAccount
  name: my-sa
  namespace: my-namespace
```

---

## Secrets Baseline (Opt-In)

The `secrets-baseline` policy bundles 2 rules implementing CIS 5.4 secrets controls. Enable via the `cis` profile.

### deny-secret-env

**Policy:** secrets-baseline | **Severity:** MEDIUM | **Controls:** CIS 5.4.1, NSA Hardening: Secrets, NIST SP 800-190 4.5.2, NIST IA-5, NIST SC-28

**Included in:** cis

**Description:** Containers must not reference Secrets via env valueFrom.secretKeyRef or envFrom.secretRef; mount them as files.

**Denied manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-creds
          key: password
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    volumeMounts:
    - name: secret-vol
      mountPath: /run/secrets
      readOnly: true
  volumes:
  - name: secret-vol
    secret:
      secretName: db-creds
```

---

### flag-configmap-sensitive

**Policy:** secrets-baseline | **Severity:** MEDIUM | **Controls:** CIS 5.4.1, NSA Hardening: Secrets, NIST SP 800-190 4.5.2, NIST IA-5, NIST SC-28

**Included in:** cis

**Description:** ConfigMaps must not contain keys that look like credentials (password, token, secret, apikey, api_key, private_key, privatekey, credential).

**Denied manifest:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bad-config
data:
  api_token: "sk-abc123def456"
  app-config: |
    log_level: info
```

**Allowed manifest:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: good-config
data:
  app-config: |
    log_level: info
    feature_flags: enabled
```

---

## Network Baseline (Opt-In)

The `network-baseline` policy bundles 2 rules implementing CIS 5.3 NetworkPolicy and Ingress controls. Enable via the `cis` profile.

### deny-overly-broad-netpol

**Policy:** network-baseline | **Severity:** MEDIUM | **Controls:** CIS 5.3.2, NSA Hardening: Network Separation, NIST SP 800-190 4.3.2, NIST SC-7

**Included in:** cis

**Description:** NetworkPolicies must not combine an empty podSelector with an allow-all ingress rule.

**Denied manifest:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bad-netpol
spec:
  podSelector: {}
  ingress:
  - from: []
```

**Allowed manifest:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: good-netpol
spec:
  podSelector:
    matchLabels:
      app: myapp
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: kube-policies-system
```

---

### ingress-require-tls-no-wildcard

**Policy:** network-baseline | **Severity:** MEDIUM | **Controls:** CIS 5.3.1, NSA Hardening: Network Separation, NIST SC-7, NIST SC-7(5), NIST SC-8

**Included in:** cis

**Description:** Ingress objects must define TLS and must not use wildcard hosts.

**Denied manifest:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bad-ingress
spec:
  rules:
  - host: "*.example.com"
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: myapp
            port:
              number: 80
```

**Allowed manifest:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: good-ingress
spec:
  tls:
  - hosts:
    - app.example.com
    secretName: tls-cert
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: myapp
            port:
              number: 80
```

---

## Mutating Hardening (Opt-In)

The `mutating-hardening` policy bundles 1 rule that auto-defaults security hardening. This is a mutating rule (emits RFC6902 JSON patches), not a deny rule. Enable via the `pss-restricted-mutating` profile.

### harden-pod-securitycontext

**Policy:** mutating-hardening | **Severity:** MEDIUM | **Controls:** PSS Restricted: SecurityContext Defaults, NSA Hardening: Pod, NIST SP 800-190 4.4.2, NIST CM-6, NIST CM-7

**Included in:** pss-restricted-mutating

**Description:** Emit RFC6902 patches that default missing securityContext hardening fields (seccomp, allowPrivilegeEscalation=false, drop ALL, readOnlyRootFilesystem=true, runAsNonRoot=true, automountServiceAccountToken=false).

**Example pod before mutation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod
spec:
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
```

**After mutation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod
spec:
  automountServiceAccountToken: false
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:v1.0.0@sha256:abcd1234
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
```

---

## Enforcement Profiles

All enforcement profiles except `security-baseline` (always on) are **opt-in**. Select one or more via `spec.profiles:` in the Helm values or the Policy CRD.

See [Policy Profiles](policy-profiles.md) for the complete profile catalog.

---

## Exception Path (PolicyException CRs)

Operators can suppress rule violations on a per-namespace, per-resource, or per-user basis using `PolicyException` custom resources. This is the only supported way to create exceptions; inline exceptions in the admission controller config are deprecated.

**Example exception suppressing `require-drop-all-capabilities` in the `kube-system` namespace:**

```yaml
apiVersion: policies.kube-policies.io/v1
kind: PolicyException
metadata:
  name: system-namespace-exemption
  namespace: kube-policies-system
spec:
  rules:
  - require-drop-all-capabilities
  namespaces:
  - kube-system
  approval:
    required: true
    approvers:
    - security-team
    duration: 30d
```

For the full exception format and validation rules, see [examples/policies/security-baseline.yaml](../examples/policies/security-baseline.yaml) (the `exceptions:` block).

---

## Catalog Integrity

Every rule ID in `internal/policy/control_matrix.yaml` MUST appear in this document. This invariant is enforced by a Go test (`catalog_link_test.go`) that parses this markdown file and asserts all 30 engine rule IDs are substrings of the content.
