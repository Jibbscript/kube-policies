# Policy Control Matrix

This document is GENERATED FROM `/internal/policy/control_matrix.yaml` (the authoritative, machine-checkable source). It is kept in sync by `control_matrix_test.go`, which enforces:

- Every bundled rule appears here exactly once (no missing, no orphans)
- Every rule lists at least one numbered control ID
- The rendered table structure matches the YAML source

## Rule-to-Control Mapping

| Rule ID | Owning Policy | Severity | Control IDs |
|---------|---------------|----------|------------|
| **security-baseline** |
| no-privileged-containers | security-baseline | HIGH | CIS 5.2.2, PSS Baseline: Privileged Containers, NIST SP 800-190 4.4.2, NIST AC-6 |
| no-host-path-volumes | security-baseline | HIGH | CIS 5.2.12, PSS Baseline: HostPath Volumes, NIST SP 800-190 4.3.4, NIST CM-7 |
| no-latest-image-tag | security-baseline | MEDIUM | CIS 5.7.4, NIST SP 800-190 4.1.2, NIST CM-2 |
| required-security-context | security-baseline | MEDIUM | CIS 5.2.6, PSS Restricted: Running as Non-root, NIST SP 800-190 4.4.2, NIST AC-6 |
| **image-provenance** |
| allowed-registries | image-provenance | HIGH | NSA Hardening: Supply Chain, NIST SP 800-190 4.1.1, NIST CM-7, NIST SR-3 |
| require-image-digest | image-provenance | HIGH | NSA Hardening: Supply Chain, NIST SP 800-190 4.1.1, SLSA L2, NIST SR-4 |
| **pss-baseline** |
| deny-host-namespaces | pss-baseline | HIGH | CIS 5.2.3, CIS 5.2.4, CIS 5.2.5, PSS Baseline: Host Namespaces, NIST SP 800-190 4.3.4 |
| restrict-capabilities | pss-baseline | HIGH | CIS 5.2.8, CIS 5.2.9, PSS Baseline: Capabilities, NIST SP 800-190 4.4.2, NIST AC-6 |
| deny-host-port | pss-baseline | MEDIUM | CIS 5.2.4, PSS Baseline: HostPorts, NSA Hardening: Pod |
| seccomp-not-unconfined | pss-baseline | HIGH | CIS 5.2.7, PSS Baseline: Seccomp, NIST SP 800-190 4.4.4 |
| deny-unsafe-sysctls | pss-baseline | MEDIUM | CIS 5.2.7, PSS Baseline: Sysctls, NIST SP 800-190 4.4.4 |
| deny-apparmor-unconfined | pss-baseline | HIGH | CIS 5.2.7, PSS Baseline: AppArmor, NIST SP 800-190 4.4.4 |
| **pss-restricted** |
| require-no-privilege-escalation | pss-restricted | HIGH | CIS 5.2.5, PSS Restricted: Privilege Escalation, NIST SP 800-190 4.4.2, NIST AC-6 |
| require-drop-all-capabilities | pss-restricted | HIGH | CIS 5.2.9, PSS Restricted: Capabilities, NIST SP 800-190 4.4.2, NIST AC-6 |
| require-readonly-rootfs | pss-restricted | MEDIUM | PSS Restricted: Read-only Root Filesystem, NSA Hardening: Pod, NIST SP 800-190 4.4.1, NIST CM-7 |
| require-run-as-nonroot | pss-restricted | HIGH | CIS 5.2.6, PSS Restricted: Running as Non-root, NIST SP 800-190 4.4.2, NIST AC-6 |
| restrict-volume-types | pss-restricted | MEDIUM | CIS 5.2.4, PSS Restricted: Volume Types, NIST SP 800-190 4.3.4 |
| **nsa-hardening** |
| require-resource-limits | nsa-hardening | MEDIUM | CIS 5.7.3, NSA Hardening: Resource Limits, NIST SP 800-190 4.3.3, NIST SC-6 |
| require-automount-token-disabled | nsa-hardening | MEDIUM | CIS 5.1.5, CIS 5.1.6, NSA Hardening: RBAC, NIST SP 800-190 4.2.4, NIST AC-6 |
| **governance-baseline** |
| require-labels | governance-baseline | LOW | CIS 5.7.1, NIST CM-8, NIST CM-8(1), NIST SP 800-190 4.3.1 |
| deny-default-namespace | governance-baseline | LOW | CIS 5.7.1, NSA Hardening: Namespaces, NIST SP 800-190 4.3.1, NIST CM-8 |
| **rbac-baseline** |
| deny-wildcard-rbac | rbac-baseline | HIGH | CIS 5.1.3, NSA Hardening: RBAC, NIST SP 800-190 4.2.4, NIST AC-6, NIST AC-6(1) |
| deny-dangerous-verbs | rbac-baseline | HIGH | CIS 5.1.1, CIS 5.1.4, NSA Hardening: RBAC, NIST AC-6, NIST AC-6(1) |
| deny-cluster-admin-binding | rbac-baseline | HIGH | CIS 5.1.1, CIS 5.1.2, NSA Hardening: RBAC, NIST AC-6, NIST AC-3 |
| deny-broad-subject-binding | rbac-baseline | HIGH | CIS 5.1.1, CIS 5.1.6, NSA Hardening: RBAC, NIST AC-6, NIST AC-6(1) |
| **secrets-baseline** |
| deny-secret-env | secrets-baseline | MEDIUM | CIS 5.4.1, NSA Hardening: Secrets, NIST SP 800-190 4.5.2, NIST IA-5, NIST SC-28 |
| flag-configmap-sensitive | secrets-baseline | MEDIUM | CIS 5.4.1, NSA Hardening: Secrets, NIST SP 800-190 4.5.2, NIST IA-5, NIST SC-28 |
| **network-baseline** |
| deny-overly-broad-netpol | network-baseline | MEDIUM | CIS 5.3.2, NSA Hardening: Network Separation, NIST SP 800-190 4.3.2, NIST SC-7 |
| ingress-require-tls-no-wildcard | network-baseline | MEDIUM | CIS 5.3.1, NSA Hardening: Network Separation, NIST SC-7, NIST SC-7(5), NIST SC-8 |
| **mutating-hardening** |
| harden-pod-securitycontext | mutating-hardening | MEDIUM | PSS Restricted: SecurityContext Defaults, NSA Hardening: Pod, NIST SP 800-190 4.4.2, NIST CM-6, NIST CM-7 |
