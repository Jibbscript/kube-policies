package policy

import "time"

// This file defines the bundled policy packs added in P10 (POL-WU-03..POL-WU-20).
//
// Every pack ships DISABLED by default (Enabled:false). They are activated by
// selecting an enforcement profile (POL-WU-23) so a deploy that only wants the
// original security-baseline is never silently broken on upgrade — the same
// opt-in discipline the bundled image-provenance policy already follows.
//
// All rules:
//   - are authored against the engine contract: query data.kube_policies.evaluate
//     returning {allowed, message?, path?};
//   - import the shared library (data.kube_policies.lib) so they evaluate the
//     EFFECTIVE pod spec across workload controllers, initContainers, and
//     ephemeralContainers (POL-WU-01);
//   - emit at most one violation per rule, chosen deterministically (lowest
//     index / first in a stably-ordered list) so OPA never raises a
//     complete-document conflict;
//   - carry TargetKinds so kind routing (POL-WU-21) only evaluates them against
//     pod-bearing kinds.

// withPodKinds routes every rule in p to the pod-bearing workload kinds unless a
// rule already declares its own TargetKinds.
func withPodKinds(p *Policy) *Policy {
	for i := range p.Rules {
		if p.Rules[i].TargetKinds == nil {
			p.Rules[i].TargetKinds = podWorkloadKinds
		}
	}
	return p
}

// pssBaselinePolicy bundles the Pod Security Standards "baseline" controls that
// block the most dangerous pod configurations (POL-WU-03..06).
func pssBaselinePolicy() *Policy {
	now := time.Now()
	return withPodKinds(&Policy{
		ID:          "pss-baseline",
		Name:        "Pod Security Standards — Baseline",
		Description: "PSS-Baseline guardrails: host namespaces, dangerous capabilities, hostPort, seccomp/AppArmor/sysctls",
		Version:     "1.0.0",
		Enabled:     false, // opt-in; activated via enforcement profile (POL-WU-23)
		CreatedAt:   now,
		UpdatedAt:   now,
		Rules: []Rule{
			{
				ID:          "deny-host-namespaces",
				Name:        "Deny Host Namespaces",
				Description: "Pods must not share the host network, PID, or IPC namespaces",
				Severity:    "HIGH",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.3", "CIS-5.2.4", "CIS-5.2.5", "PSS-Baseline", "NSA-Hardening-Pod", "NIST SP 800-190 4.3.4"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

host_namespace_violations := vs if {
	checks := [
		{"field": "hostNetwork", "set": object.get(lib.pod_spec, "hostNetwork", false)},
		{"field": "hostPID", "set": object.get(lib.pod_spec, "hostPID", false)},
		{"field": "hostIPC", "set": object.get(lib.pod_spec, "hostIPC", false)},
	]
	vs := [c | some c in checks; c.set == true]
}

evaluate := {
	"allowed": false,
	"message": sprintf("Pod must not share the host namespace (%s=true)", [v.field]),
	"path": sprintf("%s.%s", [lib.container_path_prefix, v.field]),
} if {
	count(host_namespace_violations) > 0
	v := host_namespace_violations[0]
}
`,
			},
			{
				ID:          "restrict-capabilities",
				Name:        "Restrict Added Capabilities",
				Description: "Containers may only add NET_BIND_SERVICE; NET_RAW, SYS_ADMIN and other capabilities are denied",
				Severity:    "HIGH",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.8", "CIS-5.2.9", "PSS-Baseline", "PSS-Restricted", "NIST SP 800-190 4.4.2", "NIST AC-6"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

allowed_caps := {"NET_BIND_SERVICE"}

added_caps(c) := object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])

disallowed_caps(c) := [upper(x) |
	some x in added_caps(c)
	not upper(x) in allowed_caps
]

evaluate := {
	"allowed": false,
	"message": sprintf("Container '%s' adds disallowed capability %q (baseline permits only NET_BIND_SERVICE)", [entry.container.name, cap]),
	"path": sprintf("%s.securityContext.capabilities.add", [entry.path]),
} if {
	offending := [e |
		some e in lib.containers_with_paths
		count(disallowed_caps(e.container)) > 0
	]
	count(offending) > 0
	entry := offending[0]
	cap := disallowed_caps(entry.container)[0]
}
`,
			},
			{
				ID:          "deny-host-port",
				Name:        "Deny hostPort",
				Description: "Containers must not bind a hostPort",
				Severity:    "MEDIUM",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.4", "PSS-Baseline", "NSA-Hardening-Pod"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

has_host_port(c) if {
	some p in object.get(c, "ports", [])
	object.get(p, "hostPort", 0) != 0
}

evaluate := {
	"allowed": false,
	"message": sprintf("Container '%s' must not bind a hostPort", [entry.container.name]),
	"path": sprintf("%s.ports", [entry.path]),
} if {
	offending := [e |
		some e in lib.containers_with_paths
		has_host_port(e.container)
	]
	count(offending) > 0
	entry := offending[0]
}
`,
			},
			{
				ID:          "seccomp-not-unconfined",
				Name:        "Seccomp Not Unconfined",
				Description: "Pod and container seccompProfile.type must not be Unconfined",
				Severity:    "HIGH",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.7", "PSS-Baseline", "PSS-Restricted", "NSA-Hardening-Pod", "NIST SP 800-190 4.4.4"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

pod_seccomp_unconfined if object.get(object.get(lib.pod_security_context, "seccompProfile", {}), "type", "") == "Unconfined"

container_seccomp_unconfined(c) if object.get(object.get(object.get(c, "securityContext", {}), "seccompProfile", {}), "type", "") == "Unconfined"

seccomp_violations := vs if {
	pod := [{"message": "Pod seccompProfile.type must not be Unconfined", "path": sprintf("%s.securityContext.seccompProfile.type", [lib.container_path_prefix])} |
		pod_seccomp_unconfined
	]
	cs := [{"message": sprintf("Container '%s' seccompProfile.type must not be Unconfined", [e.container.name]), "path": sprintf("%s.securityContext.seccompProfile.type", [e.path])} |
		some e in lib.containers_with_paths
		container_seccomp_unconfined(e.container)
	]
	vs := array.concat(pod, cs)
}

evaluate := {
	"allowed": false,
	"message": v.message,
	"path": v.path,
} if {
	count(seccomp_violations) > 0
	v := seccomp_violations[0]
}
`,
			},
			{
				ID:          "deny-unsafe-sysctls",
				Name:        "Deny Unsafe Sysctls",
				Description: "Pods may only set the PSS-Baseline safe sysctls",
				Severity:    "MEDIUM",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.7", "PSS-Baseline", "NSA-Hardening-Pod", "NIST SP 800-190 4.4.4"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

# PSS-Baseline safe sysctls (all others are unsafe under baseline).
safe_sysctls := {
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.ip_unprivileged_port_start",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
	"net.ipv4.ip_local_reserved_ports",
}

unsafe_sysctls := [s |
	some s in object.get(lib.pod_security_context, "sysctls", [])
	not s.name in safe_sysctls
]

evaluate := {
	"allowed": false,
	"message": sprintf("Pod sets unsafe sysctl %q (PSS-Baseline permits only a safe set)", [s.name]),
	"path": sprintf("%s.securityContext.sysctls", [lib.container_path_prefix]),
} if {
	count(unsafe_sysctls) > 0
	s := unsafe_sysctls[0]
}
`,
			},
			{
				ID:          "deny-apparmor-unconfined",
				Name:        "Deny AppArmor Unconfined",
				Description: "Containers must not disable AppArmor (appArmorProfile.type=Unconfined or the legacy unconfined annotation)",
				Severity:    "HIGH",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.7", "PSS-Baseline", "NSA-Hardening-Pod", "NIST SP 800-190 4.4.4"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

pod_apparmor_unconfined if object.get(object.get(lib.pod_security_context, "appArmorProfile", {}), "type", "") == "Unconfined"

container_apparmor_unconfined(c) if object.get(object.get(object.get(c, "securityContext", {}), "appArmorProfile", {}), "type", "") == "Unconfined"

annotation_unconfined := [k |
	some k, v in object.get(lib.pod_meta, "annotations", {})
	startswith(k, "container.apparmor.security.beta.kubernetes.io/")
	v == "unconfined"
]

apparmor_violations := vs if {
	pod := [{"message": "Pod appArmorProfile.type must not be Unconfined", "path": sprintf("%s.securityContext.appArmorProfile.type", [lib.container_path_prefix])} |
		pod_apparmor_unconfined
	]
	cs := [{"message": sprintf("Container '%s' appArmorProfile.type must not be Unconfined", [e.container.name]), "path": sprintf("%s.securityContext.appArmorProfile.type", [e.path])} |
		some e in lib.containers_with_paths
		container_apparmor_unconfined(e.container)
	]
	ann := [{"message": sprintf("AppArmor annotation %q must not be 'unconfined'", [k]), "path": sprintf("%s.metadata.annotations", [lib.container_path_prefix])} |
		some k in annotation_unconfined
	]
	vs := array.concat(array.concat(pod, cs), ann)
}

evaluate := {
	"allowed": false,
	"message": v.message,
	"path": v.path,
} if {
	count(apparmor_violations) > 0
	v := apparmor_violations[0]
}
`,
			},
		},
	})
}

// pssRestrictedPolicy bundles the Pod Security Standards "restricted" controls
// on top of baseline (POL-WU-07..11).
func pssRestrictedPolicy() *Policy {
	now := time.Now()
	return withPodKinds(&Policy{
		ID:          "pss-restricted",
		Name:        "Pod Security Standards — Restricted",
		Description: "PSS-Restricted guardrails: no privilege escalation, drop ALL caps, read-only rootfs, run-as-non-root, restricted volume types",
		Version:     "1.0.0",
		Enabled:     false, // opt-in; activated via enforcement profile (POL-WU-23)
		CreatedAt:   now,
		UpdatedAt:   now,
		Rules: []Rule{
			{
				ID:          "require-no-privilege-escalation",
				Name:        "Require allowPrivilegeEscalation=false",
				Description: "Every container must set securityContext.allowPrivilegeEscalation=false",
				Severity:    "HIGH",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.5", "PSS-Restricted", "NIST SP 800-190 4.4.2", "NIST AC-6"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

# Missing or true both violate; only an explicit false satisfies the rule.
violating(c) if object.get(object.get(c, "securityContext", {}), "allowPrivilegeEscalation", true) != false

evaluate := {
	"allowed": false,
	"message": sprintf("Container '%s' must set allowPrivilegeEscalation=false", [entry.container.name]),
	"path": sprintf("%s.securityContext.allowPrivilegeEscalation", [entry.path]),
} if {
	offending := [e | some e in lib.containers_with_paths; violating(e.container)]
	count(offending) > 0
	entry := offending[0]
}
`,
			},
			{
				ID:          "require-drop-all-capabilities",
				Name:        "Require capabilities drop ALL",
				Description: "Every container must drop ALL capabilities",
				Severity:    "HIGH",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.9", "PSS-Restricted", "NIST SP 800-190 4.4.2", "NIST AC-6"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

dropped(c) := {upper(d) | some d in object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "drop", [])}

violating(c) if not "ALL" in dropped(c)

evaluate := {
	"allowed": false,
	"message": sprintf("Container '%s' must drop ALL capabilities (securityContext.capabilities.drop must include \"ALL\")", [entry.container.name]),
	"path": sprintf("%s.securityContext.capabilities.drop", [entry.path]),
} if {
	offending := [e | some e in lib.containers_with_paths; violating(e.container)]
	count(offending) > 0
	entry := offending[0]
}
`,
			},
			{
				ID:          "require-readonly-rootfs",
				Name:        "Require read-only root filesystem",
				Description: "Every container must set securityContext.readOnlyRootFilesystem=true",
				Severity:    "MEDIUM",
				Category:    "Security",
				Frameworks:  []string{"PSS-Restricted", "NSA-Hardening-Pod", "NIST SP 800-190 4.4.1", "NIST CM-7"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

violating(c) if object.get(object.get(c, "securityContext", {}), "readOnlyRootFilesystem", false) != true

evaluate := {
	"allowed": false,
	"message": sprintf("Container '%s' must set readOnlyRootFilesystem=true", [entry.container.name]),
	"path": sprintf("%s.securityContext.readOnlyRootFilesystem", [entry.path]),
} if {
	offending := [e | some e in lib.containers_with_paths; violating(e.container)]
	count(offending) > 0
	entry := offending[0]
}
`,
			},
			{
				ID:          "require-run-as-nonroot",
				Name:        "Require run as non-root",
				Description: "Pods must run as non-root (runAsNonRoot at pod or every container) and must not set runAsUser=0",
				Severity:    "HIGH",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.6", "PSS-Restricted", "NIST SP 800-190 4.4.2", "NIST AC-6"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

pod_runs_nonroot if object.get(lib.pod_security_context, "runAsNonRoot", false) == true

container_runs_nonroot(c) if object.get(object.get(c, "securityContext", {}), "runAsNonRoot", false) == true

runasuser0(sc) if object.get(sc, "runAsUser", -1) == 0

violations := vs if {
	uid0_pod := [{"message": "Pod must not set runAsUser=0 (root)", "path": sprintf("%s.securityContext.runAsUser", [lib.container_path_prefix])} |
		runasuser0(lib.pod_security_context)
	]
	uid0_c := [{"message": sprintf("Container '%s' must not set runAsUser=0 (root)", [e.container.name]), "path": sprintf("%s.securityContext.runAsUser", [e.path])} |
		some e in lib.containers_with_paths
		runasuser0(object.get(e.container, "securityContext", {}))
	]
	nonroot := [{"message": sprintf("Container '%s' must run as non-root (set runAsNonRoot=true at pod or container scope)", [e.container.name]), "path": sprintf("%s.securityContext.runAsNonRoot", [e.path])} |
		some e in lib.containers_with_paths
		not pod_runs_nonroot
		not container_runs_nonroot(e.container)
	]
	vs := array.concat(array.concat(uid0_pod, uid0_c), nonroot)
}

evaluate := {
	"allowed": false,
	"message": v.message,
	"path": v.path,
} if {
	count(violations) > 0
	v := violations[0]
}
`,
			},
			{
				ID:          "restrict-volume-types",
				Name:        "Restrict Volume Types",
				Description: "Pod volumes must use only the PSS-Restricted allowed volume types",
				Severity:    "MEDIUM",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.2.4", "PSS-Restricted", "NIST SP 800-190 4.3.4"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

allowed_volume_types := {
	"configMap", "csi", "downwardAPI", "emptyDir",
	"ephemeral", "persistentVolumeClaim", "projected", "secret",
}

volume_disallowed(v) if {
	some k, _ in v
	k != "name"
	not k in allowed_volume_types
}

disallowed_type(v) := t if {
	bad := sort([k |
		some k, _ in v
		k != "name"
		not k in allowed_volume_types
	])
	t := bad[0]
}

bad_indices := [i |
	some i, v in lib.volumes
	volume_disallowed(v)
]

evaluate := {
	"allowed": false,
	"message": sprintf("Volume '%s' uses disallowed type %q (PSS-Restricted volume-type allowlist)", [object.get(v, "name", ""), disallowed_type(v)]),
	"path": sprintf("%s.volumes[%d]", [lib.container_path_prefix, i]),
} if {
	count(bad_indices) > 0
	i := min(bad_indices)
	v := lib.volumes[i]
}
`,
			},
		},
	})
}

// nsaHardeningPolicy bundles NSA/CISA + NIST SP 800-190 hardening controls not
// covered by the PSS packs (POL-WU-12, POL-WU-15). Registry allowlist and
// image-digest pinning live in the image-provenance policy (POL-WU-13/14).
func nsaHardeningPolicy() *Policy {
	now := time.Now()
	return withPodKinds(&Policy{
		ID:          "nsa-hardening",
		Name:        "NSA/CISA + NIST 800-190 Hardening",
		Description: "Resource limits and service-account token hardening",
		Version:     "1.0.0",
		Enabled:     false, // opt-in; activated via enforcement profile (POL-WU-23)
		CreatedAt:   now,
		UpdatedAt:   now,
		Rules: []Rule{
			{
				ID:          "require-resource-limits",
				Name:        "Require Resource Requests and Limits",
				Description: "Every container must set CPU and memory requests and limits",
				Severity:    "MEDIUM",
				Category:    "Resource",
				Frameworks:  []string{"NSA-Hardening-ResourceLimits", "NIST SP 800-190 4.3.3", "NIST SC-6", "CIS-5.7.3"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

has_all_resources(c) if {
	res := object.get(c, "resources", {})
	object.get(object.get(res, "limits", {}), "cpu", "") != ""
	object.get(object.get(res, "limits", {}), "memory", "") != ""
	object.get(object.get(res, "requests", {}), "cpu", "") != ""
	object.get(object.get(res, "requests", {}), "memory", "") != ""
}

evaluate := {
	"allowed": false,
	"message": sprintf("Container '%s' must declare CPU and memory requests and limits", [entry.container.name]),
	"path": sprintf("%s.resources", [entry.path]),
} if {
	offending := [e | some e in lib.containers_with_paths; not has_all_resources(e.container)]
	count(offending) > 0
	entry := offending[0]
}
`,
			},
			{
				ID:          "require-automount-token-disabled",
				Name:        "Disable ServiceAccount Token Automount",
				Description: "automountServiceAccountToken must be explicitly false unless the workload opts in",
				Severity:    "MEDIUM",
				Category:    "Security",
				Frameworks:  []string{"CIS-5.1.5", "CIS-5.1.6", "NSA-Hardening-RBAC", "NIST SP 800-190 4.2.4", "NIST AC-6"},
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

# Escape hatch for workloads that legitimately call the API server.
opt_in if object.get(object.get(lib.pod_meta, "annotations", {}), "policy.kube-policies.io/allow-automount-token", "") == "true"

evaluate := {
	"allowed": false,
	"message": "automountServiceAccountToken must be explicitly set to false (or opt in via the policy.kube-policies.io/allow-automount-token annotation)",
	"path": sprintf("%s.automountServiceAccountToken", [lib.container_path_prefix]),
} if {
	not opt_in
	object.get(lib.pod_spec, "automountServiceAccountToken", true) != false
}
`,
			},
		},
	})
}

// governanceBaselinePolicy bundles FedRAMP inventory / namespace-isolation
// governance controls (POL-WU-20).
func governanceBaselinePolicy() *Policy {
	now := time.Now()
	return withPodKinds(&Policy{
		ID:          "governance-baseline",
		Name:        "Governance Baseline",
		Description: "Mandatory ownership/classification labels and a ban on the default namespace",
		Version:     "1.0.0",
		Enabled:     false, // opt-in; activated via enforcement profile (POL-WU-23)
		CreatedAt:   now,
		UpdatedAt:   now,
		// requiredLabels is the comma-separated set of mandatory labels
		// (POL-WU-20); operators override via spec.parameters.
		Parameters: map[string]string{
			"requiredLabels": "app.kubernetes.io/name,owner,data-classification",
		},
		Rules: []Rule{
			{
				ID:          "require-labels",
				Name:        "Require Ownership/Classification Labels",
				Description: "Workloads must carry the mandatory inventory labels (CM-8)",
				Severity:    "LOW",
				Category:    "Governance",
				Frameworks:  []string{"NIST CM-8", "NIST CM-8(1)", "NSA-Hardening-Namespace", "CIS-5.7.1", "NIST SP 800-190 4.3.1"},
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

required_labels := {trim_space(l) |
	some l in split(object.get(input.parameters, "requiredLabels", "app.kubernetes.io/name,owner,data-classification"), ",")
	trim_space(l) != ""
}

labels := object.get(object.get(input.object, "metadata", {}), "labels", {})

missing := sort([l |
	some l in required_labels
	not labels[l]
])

evaluate := {
	"allowed": false,
	"message": sprintf("Workload is missing required label %q", [missing[0]]),
	"path": sprintf("metadata.labels[%q]", [missing[0]]),
} if {
	count(missing) > 0
}
`,
			},
			{
				ID:          "deny-default-namespace",
				Name:        "Deny Default Namespace",
				Description: "Workloads must not be created in the default namespace",
				Severity:    "LOW",
				Category:    "Governance",
				Frameworks:  []string{"NSA-Hardening-Namespace", "CIS-5.7.1", "NIST SP 800-190 4.3.1", "NIST CM-8"},
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": "Workloads must not be created in the 'default' namespace",
	"path": "metadata.namespace",
} if {
	object.get(object.get(input.object, "metadata", {}), "namespace", "") == "default"
}
`,
			},
		},
	})
}

// mutatingHardeningPolicy bundles the auto-hardening mutation rule (POL-WU-22).
// It is opt-in (activated via the pss-restricted-mutating profile) and scoped to
// bare Pods — the object that actually runs — so its JSONPatch paths target
// /spec directly. Standard admission ordering applies the mutation before the
// validating webhooks run, so a pod the deny rules would reject is hardened
// first. The rule only DEFAULTS missing fields; it never clobbers an explicit
// operator setting.
func mutatingHardeningPolicy() *Policy {
	now := time.Now()
	return &Policy{
		ID:          "mutating-hardening",
		Name:        "Mutating Hardening Defaults",
		Description: "Auto-default pod/container securityContext to PSS-Restricted when unset (seccomp, no-priv-escalation, drop ALL, read-only rootfs, run-as-non-root, automount=false)",
		Version:     "1.0.0",
		Enabled:     false, // opt-in; activated via the pss-restricted-mutating profile (POL-WU-23)
		CreatedAt:   now,
		UpdatedAt:   now,
		Rules: []Rule{
			{
				ID:          "harden-pod-securitycontext",
				Name:        "Harden Pod SecurityContext",
				Description: "Emit RFC6902 patches that default missing securityContext hardening fields",
				Severity:    "MEDIUM",
				Category:    "Mutation",
				Frameworks:  []string{"PSS-Restricted", "NSA-Hardening-Pod", "NIST SP 800-190 4.4.2", "NIST CM-6", "NIST CM-7"},
				TargetKinds: []string{"Pod"},
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

# allowed stays true: this is a mutation, not a denial. Patches are surfaced only
# when there is at least one to apply (otherwise the default fires).
evaluate := {"allowed": true, "patches": all_patches} if {
	count(all_patches) > 0
}

# Wholesale hardened securityContext for containers that declare none.
hardened_sc := {
	"allowPrivilegeEscalation": false,
	"runAsNonRoot": true,
	"readOnlyRootFilesystem": true,
	"capabilities": {"drop": ["ALL"]},
}

all_patches := array.concat(pod_patches, container_patches)

# ---- pod level: seccomp + automount ----
pod_patches := array.concat(seccomp_patches, automount_patches)

seccomp_patches := [{"op": "add", "path": "/spec/securityContext", "value": {"seccompProfile": {"type": "RuntimeDefault"}}}] if {
	not input.object.spec.securityContext
}

seccomp_patches := [{"op": "add", "path": "/spec/securityContext/seccompProfile", "value": {"type": "RuntimeDefault"}}] if {
	input.object.spec.securityContext
	not input.object.spec.securityContext.seccompProfile
}

seccomp_patches := [] if {
	input.object.spec.securityContext.seccompProfile
}

automount_present if input.object.spec.automountServiceAccountToken == true

automount_present if input.object.spec.automountServiceAccountToken == false

automount_patches := [{"op": "add", "path": "/spec/automountServiceAccountToken", "value": false}] if {
	not automount_present
}

automount_patches := [] if {
	automount_present
}

# ---- container level: regular + init ----
targets := array.concat(
	[{"base": "/spec/containers", "index": i, "c": c} | some i, c in input.object.spec.containers],
	[{"base": "/spec/initContainers", "index": i, "c": c} | some i, c in object.get(input.object.spec, "initContainers", [])],
)

full_sc_patches := [{"op": "add", "path": sprintf("%s/%d/securityContext", [t.base, t.index]), "value": hardened_sc} |
	some t in targets
	not t.c.securityContext
]

field_patches := [p |
	some t in targets
	t.c.securityContext
	some p in missing_field_patches(t.base, t.index, t.c.securityContext)
]

container_patches := array.concat(full_sc_patches, field_patches)

present(sc, f) if object.get(sc, f, "__absent__") != "__absent__"

missing_field_patches(base, idx, sc) := patches if {
	ape := [{"op": "add", "path": sprintf("%s/%d/securityContext/allowPrivilegeEscalation", [base, idx]), "value": false} | not present(sc, "allowPrivilegeEscalation")]
	rnr := [{"op": "add", "path": sprintf("%s/%d/securityContext/runAsNonRoot", [base, idx]), "value": true} | not present(sc, "runAsNonRoot")]
	rorfs := [{"op": "add", "path": sprintf("%s/%d/securityContext/readOnlyRootFilesystem", [base, idx]), "value": true} | not present(sc, "readOnlyRootFilesystem")]
	caps_new := [{"op": "add", "path": sprintf("%s/%d/securityContext/capabilities", [base, idx]), "value": {"drop": ["ALL"]}} | not present(sc, "capabilities")]
	caps_drop := [{"op": "add", "path": sprintf("%s/%d/securityContext/capabilities/drop", [base, idx]), "value": ["ALL"]} |
		present(sc, "capabilities")
		not present(sc.capabilities, "drop")
	]
	patches := array.concat(array.concat(ape, rnr), array.concat(rorfs, array.concat(caps_new, caps_drop)))
}
`,
			},
		},
	}
}

// rbacBaselinePolicy bundles CIS 5.1 RBAC controls (POL-WU-16, POL-WU-17). These
// rules read RBAC objects (input.object.rules / roleRef / subjects), NOT pod
// specs, so kind routing (POL-WU-21) is what lets them coexist with the pod
// packs in one engine.
func rbacBaselinePolicy() *Policy {
	now := time.Now()
	roleKinds := []string{"Role", "ClusterRole"}
	bindingKinds := []string{"RoleBinding", "ClusterRoleBinding"}
	return &Policy{
		ID:          "rbac-baseline",
		Name:        "RBAC Baseline",
		Description: "CIS 5.1 RBAC least-privilege: no wildcards, no dangerous verbs, no cluster-admin/broad-subject bindings",
		Version:     "1.0.0",
		Enabled:     false, // opt-in; activated via enforcement profile (POL-WU-23)
		CreatedAt:   now,
		UpdatedAt:   now,
		Rules: []Rule{
			{
				ID:          "deny-wildcard-rbac",
				Name:        "Deny Wildcard RBAC",
				Description: "Roles/ClusterRoles must not grant wildcard verbs, resources, or apiGroups",
				Severity:    "HIGH",
				Category:    "RBAC",
				Frameworks:  []string{"CIS-5.1.3", "NSA-Hardening-RBAC", "NIST SP 800-190 4.2.4", "NIST AC-6", "NIST AC-6(1)"},
				TargetKinds: roleKinds,
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

wildcard_rule(r) if "*" in object.get(r, "verbs", [])

wildcard_rule(r) if "*" in object.get(r, "resources", [])

wildcard_rule(r) if "*" in object.get(r, "apiGroups", [])

evaluate := {
	"allowed": false,
	"message": sprintf("RBAC rule %d grants a wildcard (verbs/resources/apiGroups '*'); grant explicit least-privilege permissions", [i]),
	"path": sprintf("rules[%d]", [i]),
} if {
	bad := [j |
		some j, r in object.get(input.object, "rules", [])
		wildcard_rule(r)
	]
	count(bad) > 0
	i := bad[0]
}
`,
			},
			{
				ID:          "deny-dangerous-verbs",
				Name:        "Deny Dangerous RBAC Verbs",
				Description: "Roles/ClusterRoles must not grant escalate, bind, or impersonate",
				Severity:    "HIGH",
				Category:    "RBAC",
				Frameworks:  []string{"CIS-5.1.1", "CIS-5.1.4", "NSA-Hardening-RBAC", "NIST AC-6", "NIST AC-6(1)"},
				TargetKinds: roleKinds,
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

dangerous_verbs := {"escalate", "bind", "impersonate"}

# Sorted so the reported verb is deterministic when a rule grants several.
rule_dangerous_verbs(r) := sort([lower(raw) |
	some raw in object.get(r, "verbs", [])
	lower(raw) in dangerous_verbs
])

evaluate := {
	"allowed": false,
	"message": sprintf("RBAC rule %d grants the dangerous verb %q", [i, rule_dangerous_verbs(input.object.rules[i])[0]]),
	"path": sprintf("rules[%d].verbs", [i]),
} if {
	bad := [j |
		some j, r in object.get(input.object, "rules", [])
		count(rule_dangerous_verbs(r)) > 0
	]
	count(bad) > 0
	i := bad[0]
}
`,
			},
			{
				ID:          "deny-cluster-admin-binding",
				Name:        "Deny cluster-admin Binding",
				Description: "Bindings must not reference the built-in cluster-admin ClusterRole",
				Severity:    "HIGH",
				Category:    "RBAC",
				Frameworks:  []string{"CIS-5.1.1", "CIS-5.1.2", "NSA-Hardening-RBAC", "NIST AC-6", "NIST AC-3"},
				TargetKinds: bindingKinds,
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": "Binding must not reference the built-in cluster-admin ClusterRole",
	"path": "roleRef",
} if {
	roleRef := object.get(input.object, "roleRef", {})
	roleRef.kind == "ClusterRole"
	roleRef.name == "cluster-admin"
}
`,
			},
			{
				ID:          "deny-broad-subject-binding",
				Name:        "Deny Broad-Subject Binding",
				Description: "Bindings must not grant permissions to system:authenticated, system:unauthenticated, or system:anonymous",
				Severity:    "HIGH",
				Category:    "RBAC",
				Frameworks:  []string{"CIS-5.1.1", "CIS-5.1.6", "NSA-Hardening-RBAC", "NIST AC-6", "NIST AC-6(1)"},
				TargetKinds: bindingKinds,
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

broad_subjects := {"system:authenticated", "system:unauthenticated", "system:anonymous"}

evaluate := {
	"allowed": false,
	"message": sprintf("Binding must not grant permissions to the broad subject %q", [s.name]),
	"path": "subjects",
} if {
	bad := [sub |
		some sub in object.get(input.object, "subjects", [])
		sub.name in broad_subjects
	]
	count(bad) > 0
	s := bad[0]
}
`,
			},
		},
	}
}

// secretsBaselinePolicy bundles CIS 5.4 Secrets controls (POL-WU-18): deny
// secrets exposed as environment variables (a pod-shaped rule) and flag
// plaintext-sensitive ConfigMap data (a ConfigMap rule).
func secretsBaselinePolicy() *Policy {
	now := time.Now()
	return &Policy{
		ID:          "secrets-baseline",
		Name:        "Secrets Baseline",
		Description: "CIS 5.4: forbid secrets as env vars and sensitive plaintext in ConfigMaps",
		Version:     "1.0.0",
		Enabled:     false, // opt-in; activated via enforcement profile (POL-WU-23)
		CreatedAt:   now,
		UpdatedAt:   now,
		Rules: []Rule{
			{
				ID:          "deny-secret-env",
				Name:        "Deny Secrets as Env Vars",
				Description: "Containers must not reference Secrets via env valueFrom.secretKeyRef or envFrom.secretRef; mount them as files",
				Severity:    "MEDIUM",
				Category:    "Secrets",
				Frameworks:  []string{"CIS-5.4.1", "NSA-Hardening-Secrets", "NIST SP 800-190 4.5.2", "NIST IA-5", "NIST SC-28"},
				TargetKinds: podWorkloadKinds,
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

uses_secret_env(c) if {
	some e in object.get(c, "env", [])
	e.valueFrom.secretKeyRef
}

uses_secret_env(c) if {
	some ef in object.get(c, "envFrom", [])
	ef.secretRef
}

evaluate := {
	"allowed": false,
	"message": sprintf("Container '%s' must not consume Secrets via environment variables; mount them as files instead", [entry.container.name]),
	"path": sprintf("%s.env", [entry.path]),
} if {
	offending := [e |
		some e in lib.containers_with_paths
		uses_secret_env(e.container)
	]
	count(offending) > 0
	entry := offending[0]
}
`,
			},
			{
				ID:          "flag-configmap-sensitive",
				Name:        "Flag Sensitive ConfigMap Data",
				Description: "ConfigMaps must not contain keys that look like credentials (password/token/secret/...)",
				Severity:    "MEDIUM",
				Category:    "Secrets",
				Frameworks:  []string{"CIS-5.4.1", "NSA-Hardening-Secrets", "NIST SP 800-190 4.5.2", "NIST IA-5", "NIST SC-28"},
				TargetKinds: []string{"ConfigMap"},
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

sensitive_markers := ["password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "privatekey", "credential"]

sensitive_key(k) if {
	some marker in sensitive_markers
	contains(lower(k), marker)
}

# Scan both data and binaryData: a credential base64-stored in binaryData (the
# normal landing spot for non-UTF8 content) must not evade the heuristic.
all_keys := array.concat(
	[k | some k, _ in object.get(input.object, "data", {})],
	[k | some k, _ in object.get(input.object, "binaryData", {})],
)

flagged := sort([k |
	some k in all_keys
	sensitive_key(k)
])

evaluate := {
	"allowed": false,
	"message": sprintf("ConfigMap key %q looks like a credential; store secrets in a Secret, not a ConfigMap", [flagged[0]]),
	"path": sprintf("data[%q]", [flagged[0]]),
} if {
	count(flagged) > 0
}
`,
			},
		},
	}
}

// networkBaselinePolicy bundles CIS 5.3 NetworkPolicy + Ingress controls
// (POL-WU-19). Namespace-wide default-deny PRESENCE is a cluster-posture check
// owned by the conftest gate (test/policy/network_posture.rego); these
// admission rules catch the per-object mistakes a presence check cannot.
func networkBaselinePolicy() *Policy {
	now := time.Now()
	return &Policy{
		ID:          "network-baseline",
		Name:        "Network Baseline",
		Description: "CIS 5.3: reject allow-all NetworkPolicies and unsafe Ingress (no TLS / wildcard host)",
		Version:     "1.0.0",
		Enabled:     false, // opt-in; activated via enforcement profile (POL-WU-23)
		CreatedAt:   now,
		UpdatedAt:   now,
		Rules: []Rule{
			{
				ID:          "deny-overly-broad-netpol",
				Name:        "Deny Allow-All NetworkPolicy",
				Description: "NetworkPolicies must not combine an empty podSelector with an allow-all ingress rule",
				Severity:    "MEDIUM",
				Category:    "Network",
				Frameworks:  []string{"CIS-5.3.2", "NSA-Hardening-NetworkSeparation", "NIST SP 800-190 4.3.2", "NIST SC-7"},
				TargetKinds: []string{"NetworkPolicy"},
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

spec := object.get(input.object, "spec", {})

empty_pod_selector if {
	ps := object.get(spec, "podSelector", {})
	not ps.matchLabels
	not ps.matchExpressions
}

# An ingress entry with no 'from' selector — whether the key is absent OR present
# but an empty list — allows traffic from everywhere (Kubernetes treats both
# identically as allow-all).
allow_all_ingress if {
	some r in object.get(spec, "ingress", [])
	count(object.get(r, "from", [])) == 0
}

evaluate := {
	"allowed": false,
	"message": "NetworkPolicy combines an empty podSelector with an allow-all ingress rule; scope the selector or restrict 'from'",
	"path": "spec.ingress",
} if {
	empty_pod_selector
	allow_all_ingress
}
`,
			},
			{
				ID:          "ingress-require-tls-no-wildcard",
				Name:        "Require Ingress TLS and Explicit Host",
				Description: "Ingress objects must define TLS and must not use wildcard hosts",
				Severity:    "MEDIUM",
				Category:    "Network",
				Frameworks:  []string{"CIS-5.3.1", "NSA-Hardening-NetworkSeparation", "NIST SC-7", "NIST SC-7(5)", "NIST SC-8"},
				TargetKinds: []string{"Ingress"},
				Rego: `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

spec := object.get(input.object, "spec", {})

no_tls if count(object.get(spec, "tls", [])) == 0

violations := vs if {
	tls := [{"message": "Ingress must define TLS (spec.tls)", "path": "spec.tls"} | no_tls]
	wild := [{"message": sprintf("Ingress host %q must not be a wildcard", [object.get(r, "host", "")]), "path": "spec.rules"} |
		some r in object.get(spec, "rules", [])
		startswith(object.get(r, "host", ""), "*")
	]
	vs := array.concat(tls, wild)
}

evaluate := {
	"allowed": false,
	"message": v.message,
	"path": v.path,
} if {
	count(violations) > 0
	v := violations[0]
}
`,
			},
		},
	}
}
