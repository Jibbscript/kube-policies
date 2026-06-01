# Restricted Pod Security Standard gate (CFG-WU-12).
#
# NIST SP 800-53 CM-6/CM-7 (least functionality, secure configuration),
# CIS Kubernetes Benchmark 5.2.x (Pod Security Standards), and the upstream
# Pod Security Admission "restricted" profile. This is the P5 manifest-hardening
# regression guard: the workloads the chart renders MUST satisfy the restricted
# profile, and a shipped Namespace MUST be PSA-restricted.
#
# Evaluation shape mirrors the P4 conftest gates (network.posture, sa.token):
# per-document — `input` is a single rendered object.
#
# CONTAINER COVERAGE: every rule evaluates the UNION of spec.template.spec
# containers + initContainers + ephemeralContainers (_all_containers). An
# unhardened init/ephemeral sidecar is a real bypass and is caught.
#
# EFFECTIVE-VALUE PRECEDENCE: Kubernetes container-level securityContext OVERRIDES
# pod-level at runtime, so seccomp and runAsNonRoot are evaluated with
# container-wins precedence (a hardened pod default cannot be silently undone by a
# permissive container override), matching how runAsGroup is already resolved.
#
# CONTROLS ENFORCED per in-scope container: seccompProfile in
# {RuntimeDefault, Localhost}; capabilities.drop contains ALL; no capabilities.add
# beyond NET_BIND_SERVICE; readOnlyRootFilesystem==true; allowPrivilegeEscalation
# ==false; privileged!=true; runAsNonRoot==true; runAsGroup!=0; resources
# requests+limits for cpu+memory. Per pod: no host namespaces (hostNetwork/
# hostPID/hostIPC). Per Namespace: PSA-restricted enforce/audit/warn labels.
#
# WORKLOAD-KIND SCOPE: Deployment/DaemonSet/StatefulSet (the only pod-bearing
# kinds this chart and the bundled monitoring stack ship). Bare Pod/Job/CronJob/
# ReplicaSet are intentionally out of scope — none is rendered here; if the chart
# ever ships one, extend _workload_kinds + the pod accessor.
#
# SCOPING: the workload rules are scoped to this chart's components
# (admission-webhook, policy-manager, dashboard via the app.kubernetes.io/component
# label) plus the bundled monitoring workloads (prometheus/grafana/alertmanager by
# name). Third-party objects are not evaluated so the gate never false-positives on
# manifests it does not own. NOTE: a workload that DROPS its component label would
# fall out of scope — the chart's label invariants are guarded separately by the
# sa.shared/label-drift gate (P4).
#
# Mode-safety: under --combine `input.kind` on an array is undefined (not an
# error), so every per-document rule here is a no-op; under a per-document run the
# rules evaluate against the single object. No rule raises eval_conflict.
package restricted.pss

import rego.v1

# ---------------------------------------------------------------------------
# Workload selection — only this chart's control-plane + bundled monitoring.
# ---------------------------------------------------------------------------

_workload_kinds := {"Deployment", "DaemonSet", "StatefulSet"}

_is_workload if {
	input.kind in _workload_kinds
}

# _control_plane_components are the kube-policies workloads whose pod template MUST
# meet restricted PSS. The dashboard is values-driven and hardened (seccomp
# RuntimeDefault + non-root runAsGroup 65532) as of CFG-WU-02/03, so it is gated
# here alongside the webhook/policy-manager (not merely unittest-covered).
_control_plane_components := {"admission-webhook", "policy-manager", "dashboard"}

# _monitoring_names are the bundled monitoring workloads scanned by name (they
# carry no app.kubernetes.io/component=admission-webhook|policy-manager label).
_monitoring_names := {"prometheus", "grafana", "alertmanager"}

_in_scope if {
	_is_workload
	object.get(input.metadata.labels, "app.kubernetes.io/component", "") in _control_plane_components
}

_in_scope if {
	_is_workload
	some n in _monitoring_names
	startswith(input.metadata.name, n)
}

# _pod is the pod spec carrying the security context + containers.
_pod := input.spec.template.spec

# _pod_sc is the pod-level securityContext (or {} when absent).
_pod_sc := object.get(_pod, "securityContext", {})

# _sc(c) is a container's securityContext (or {} when absent).
_sc(c) := object.get(c, "securityContext", {})

# _all_containers is the union of regular + init + ephemeral containers; every one
# must meet the restricted profile (an unhardened init/ephemeral sidecar is a real
# escape, so it is not exempt).
_all_containers := array.concat(
	array.concat(
		object.get(_pod, "containers", []),
		object.get(_pod, "initContainers", []),
	),
	object.get(_pod, "ephemeralContainers", []),
)

# ---------------------------------------------------------------------------
# Seccomp — EFFECTIVE (container-wins) profile must be RuntimeDefault/Localhost.
# A permissive container-level profile overrides a hardened pod default at
# runtime, so the container value wins when present; otherwise the pod value.
# ---------------------------------------------------------------------------

_allowed_seccomp := {"RuntimeDefault", "Localhost"}

_effective_seccomp(c) := t if {
	ct := object.get(_sc(c), ["seccompProfile", "type"], "")
	ct != ""
	t := ct
}

_effective_seccomp(c) := t if {
	object.get(_sc(c), ["seccompProfile", "type"], "") == ""
	t := object.get(_pod_sc, ["seccompProfile", "type"], "")
}

deny contains msg if {
	_in_scope
	some c in _all_containers
	not _effective_seccomp(c) in _allowed_seccomp
	msg := sprintf(
		"%s/%s container %q effective seccompProfile.type is not in {RuntimeDefault, Localhost} (container overrides pod) (CIS 5.2.x / PSS-Restricted, CFG-WU-12)",
		[input.kind, input.metadata.name, c.name],
	)
}

# ---------------------------------------------------------------------------
# capabilities.drop must contain ALL.
# ---------------------------------------------------------------------------

_drops_all(c) if {
	some cap in object.get(_sc(c), ["capabilities", "drop"], [])
	cap == "ALL"
}

deny contains msg if {
	_in_scope
	some c in _all_containers
	not _drops_all(c)
	msg := sprintf(
		"%s/%s container %q does not drop ALL capabilities (CIS 5.2.9 / PSS-Restricted, CFG-WU-12)",
		[input.kind, input.metadata.name, c.name],
	)
}

# ---------------------------------------------------------------------------
# capabilities.add — PSS-Restricted permits ONLY NET_BIND_SERVICE; re-granting any
# other capability (or re-adding a dropped one) violates the profile.
# ---------------------------------------------------------------------------

deny contains msg if {
	_in_scope
	some c in _all_containers
	some cap in object.get(_sc(c), ["capabilities", "add"], [])
	cap != "NET_BIND_SERVICE"
	msg := sprintf(
		"%s/%s container %q adds capability %q (PSS-Restricted permits only NET_BIND_SERVICE) (CIS 5.2.x, CFG-WU-12)",
		[input.kind, input.metadata.name, c.name, cap],
	)
}

# ---------------------------------------------------------------------------
# privileged != true.
# ---------------------------------------------------------------------------

deny contains msg if {
	_in_scope
	some c in _all_containers
	object.get(_sc(c), "privileged", false) == true
	msg := sprintf(
		"%s/%s container %q sets privileged: true (forbidden by PSS-Baseline/Restricted, CIS 5.2.1, CFG-WU-12)",
		[input.kind, input.metadata.name, c.name],
	)
}

# ---------------------------------------------------------------------------
# readOnlyRootFilesystem == true.
# ---------------------------------------------------------------------------

deny contains msg if {
	_in_scope
	some c in _all_containers
	object.get(_sc(c), "readOnlyRootFilesystem", false) != true
	msg := sprintf(
		"%s/%s container %q must set readOnlyRootFilesystem: true (CFG-WU-12, CIS 5.2.x hardening)",
		[input.kind, input.metadata.name, c.name],
	)
}

# ---------------------------------------------------------------------------
# allowPrivilegeEscalation == false.
# ---------------------------------------------------------------------------

deny contains msg if {
	_in_scope
	some c in _all_containers
	object.get(_sc(c), "allowPrivilegeEscalation", true) != false
	msg := sprintf(
		"%s/%s container %q must set allowPrivilegeEscalation: false (CIS 5.2.5 / PSS-Restricted, CFG-WU-12)",
		[input.kind, input.metadata.name, c.name],
	)
}

# ---------------------------------------------------------------------------
# runAsNonRoot == true (EFFECTIVE, container-wins). A container override of
# runAsNonRoot: false undoes a hardened pod default at runtime.
# ---------------------------------------------------------------------------

_effective_run_as_non_root(c) := v if {
	v := object.get(_sc(c), "runAsNonRoot", "unset")
	v != "unset"
}

_effective_run_as_non_root(c) := v if {
	object.get(_sc(c), "runAsNonRoot", "unset") == "unset"
	v := object.get(_pod_sc, "runAsNonRoot", false)
}

deny contains msg if {
	_in_scope
	some c in _all_containers
	_effective_run_as_non_root(c) != true
	msg := sprintf(
		"%s/%s container %q effective runAsNonRoot is not true (container overrides pod) (CIS 5.2.6 / PSS-Restricted, CFG-WU-12)",
		[input.kind, input.metadata.name, c.name],
	)
}

# ---------------------------------------------------------------------------
# runAsGroup != 0 (no root GID; container-wins, else pod, else absent -> fail).
# ---------------------------------------------------------------------------

_effective_run_as_group(c) := g if {
	g := object.get(_sc(c), "runAsGroup", object.get(_pod_sc, "runAsGroup", -1))
}

deny contains msg if {
	_in_scope
	some c in _all_containers
	g := _effective_run_as_group(c)
	g <= 0
	msg := sprintf(
		"%s/%s container %q must set runAsGroup to a non-root GID (got %d at pod/container level) (PSS-Restricted, CFG-WU-12)",
		[input.kind, input.metadata.name, c.name, g],
	)
}

# ---------------------------------------------------------------------------
# No host namespaces (hostNetwork / hostPID / hostIPC).
# ---------------------------------------------------------------------------

_host_ns_fields := {"hostNetwork", "hostPID", "hostIPC"}

deny contains msg if {
	_in_scope
	some f in _host_ns_fields
	object.get(_pod, f, false) == true
	msg := sprintf(
		"%s/%s sets %s: true (host namespaces are forbidden by PSS-Baseline/Restricted, CIS 5.2.2-5.2.4, CFG-WU-12)",
		[input.kind, input.metadata.name, f],
	)
}

# ---------------------------------------------------------------------------
# resources.requests + resources.limits present for cpu AND memory.
# ---------------------------------------------------------------------------

_has_resource(c, kind, res) if {
	object.get(c.resources, [kind, res], "") != ""
}

deny contains msg if {
	_in_scope
	some c in _all_containers
	some pair in [["requests", "cpu"], ["requests", "memory"], ["limits", "cpu"], ["limits", "memory"]]
	not _has_resource(c, pair[0], pair[1])
	msg := sprintf(
		"%s/%s container %q is missing resources.%s.%s (CFG-WU-12 resource-bound / DoS hardening)",
		[input.kind, input.metadata.name, c.name, pair[0], pair[1]],
	)
}

# ---------------------------------------------------------------------------
# Namespace PSA-restricted labels (per-document). Kept in this package per the
# WU even though network.posture has a sibling rule — the packages are separate.
# ---------------------------------------------------------------------------

_psa_modes := {"enforce", "audit", "warn"}

deny contains msg if {
	input.kind == "Namespace"
	some mode in _psa_modes
	label := sprintf("pod-security.kubernetes.io/%s", [mode])
	object.get(input.metadata.labels, label, "") != "restricted"
	msg := sprintf(
		"Namespace/%s is missing label %s: restricted (got %q); a shipped Namespace must enforce PSA-restricted (CIS 5.3.2 / PSS-Restricted, CFG-WU-12)",
		[input.metadata.name, label, object.get(input.metadata.labels, label, "")],
	)
}
