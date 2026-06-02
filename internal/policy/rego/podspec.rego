# podspec.rego — shared pod-spec extraction library for the bundled kube-policies
# rule set (POL-WU-01).
#
# Every bundled rule is compiled as its own `package kube_policies` module and
# queried at `data.kube_policies.evaluate` (see internal/policy/engine.go
# preparedQueryFor). This library is compiled ALONGSIDE every rule module so a
# rule can `import data.kube_policies.lib as lib` and evaluate the EFFECTIVE pod
# spec regardless of the admitted resource kind.
#
# Before this library, rules read input.object.spec.containers directly, so a
# privileged container inside a Deployment/DaemonSet/StatefulSet/Job/CronJob (the
# normal way workloads ship) — or inside an initContainer/ephemeralContainer —
# sailed through admission unchecked. That silent enforcement bypass is the
# defect this library closes (CIS 5.2.1, NIST SP 800-190 §4.3.4).
package kube_policies.lib

import rego.v1

# pod_spec is the effective PodSpec for the admitted object:
#   - CronJob:                                   spec.jobTemplate.spec.template.spec
#   - Deployment/ReplicaSet/DaemonSet/StatefulSet/Job: spec.template.spec
#   - bare Pod:                                  spec
#
# The else-chain is ordered most-nested first so a CronJob (which has
# spec.jobTemplate, not spec.template) matches before the controller clause, and
# a bare Pod (which has neither) falls through to spec. When the object has no
# spec at all (e.g. a ClusterRole), pod_spec is undefined and every pod-shaped
# rule that iterates all_containers simply does not fire.
pod_spec := s if {
	s := input.object.spec.jobTemplate.spec.template.spec
} else := s if {
	s := input.object.spec.template.spec
} else := input.object.spec

# pod_meta is the effective pod template metadata (labels/annotations live on the
# template for controllers, on metadata for bare Pods). Used by AppArmor
# annotation and label rules so they see the template, not the controller.
pod_meta := m if {
	m := input.object.spec.jobTemplate.spec.template.metadata
} else := m if {
	m := input.object.spec.template.metadata
} else := input.object.metadata

# pod_security_context is the pod-level securityContext ({} when absent) so
# callers can use object.get without tripping over a missing key.
pod_security_context := object.get(pod_spec, "securityContext", {})

# workload_containers are the primary spec.containers (empty list when absent).
workload_containers := object.get(pod_spec, "containers", [])

# init_containers are spec.initContainers (empty list when absent).
init_containers := object.get(pod_spec, "initContainers", [])

# ephemeral_containers are spec.ephemeralContainers (empty list when absent).
ephemeral_containers := object.get(pod_spec, "ephemeralContainers", [])

# all_containers is the union of regular, init, and ephemeral containers, in a
# deterministic order (containers, then initContainers, then ephemeralContainers)
# so the lowest-index single-violation contract stays stable across runs.
all_containers := array.concat(
	array.concat(workload_containers, init_containers),
	ephemeral_containers,
)

# volumes are spec.volumes (empty list when absent).
volumes := object.get(pod_spec, "volumes", [])

# container_path_prefix is the JSONPath prefix to the pod spec for the admitted
# kind, so violation paths point at the real field an operator must edit (a
# Deployment's container lives at spec.template.spec.containers, not
# spec.containers).
container_path_prefix := "spec.jobTemplate.spec.template.spec" if {
	input.object.spec.jobTemplate
} else := "spec.template.spec" if {
	input.object.spec.template
} else := "spec"

# containers_with_paths pairs every container (regular, then init, then
# ephemeral) with a kind-correct JSONPath locating it under the effective pod
# spec. Rules iterate this and report the lowest-index match so the
# single-violation-per-rule determinism contract is preserved while the reported
# path stays accurate for the real resource shape.
containers_with_paths := cs if {
	prefix := container_path_prefix
	regular := [{"container": c, "path": sprintf("%s.containers[%d]", [prefix, i])} |
		some i
		c := workload_containers[i]
	]
	inits := [{"container": c, "path": sprintf("%s.initContainers[%d]", [prefix, i])} |
		some i
		c := init_containers[i]
	]
	ephem := [{"container": c, "path": sprintf("%s.ephemeralContainers[%d]", [prefix, i])} |
		some i
		c := ephemeral_containers[i]
	]
	cs := array.concat(array.concat(regular, inits), ephem)
}

# is_pod_shaped is true when the admitted object exposes a pod spec — used by
# rules and tests to assert applicability without importing engine kind routing.
is_pod_shaped if pod_spec
