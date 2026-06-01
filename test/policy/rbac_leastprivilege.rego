# RBAC least-privilege gate (IAM-WU-17).
#
# Fails the build when a rendered ClusterRole/Role rule grants access to
# Secrets (or Secrets subresources) in any of the core API groups, or uses
# an RBAC wildcard ("*"). This is the regression guard for the per-component
# least-privilege split (IAM-WU-08/09/10): the settled chart grants only CRD
# access (policies.kube-policies.io), namespaced leases + events (leader
# election), dashboard service reads, and — in tokenreview mode —
# authentication.k8s.io/tokenreviews:create. None of those touch Secrets or
# wildcards, so all current rules MUST pass.
package rbac.leastprivilege

import rego.v1

# Only evaluate RBAC role documents. Null-guard input.kind so comment-only or
# empty YAML documents (which render to null) are skipped instead of erroring.
is_rbac_role if {
	input.kind == "ClusterRole"
}

is_rbac_role if {
	input.kind == "Role"
}

# scope_label returns "cluster-wide" for ClusterRoles and "namespaced" for
# Roles so deny messages name the correct scope (NIT-1).
scope_label := "cluster-wide" if {
	input.kind == "ClusterRole"
}

scope_label := "namespaced" if {
	input.kind == "Role"
}

# to_set turns a (possibly absent) list field into a set for membership tests.
to_set(xs) := {x | some x in xs}

# resource_is_secrets is true for the literal resource name "secrets" AND for
# any subresource whose first path segment is "secrets" (e.g. "secrets/status",
# "secrets/data" — LOW-1 evasion path). split(r,"/")[0] isolates the base
# resource regardless of subresource suffix.
resource_is_secrets(r) if {
	r == "secrets"
}

resource_is_secrets(r) if {
	r != "secrets"
	split(r, "/")[0] == "secrets"
}

resource_is_secrets(r) if {
	r == "*"
}

# rule_grants_secrets is true when the rule reaches Secrets (including
# subresources) via the core API group. The core group is addressed as ""
# (empty string) in RBAC rules; some tools mistakenly emit "core" as a literal
# string, so we match both. "*" in apiGroups also covers everything.
rule_grants_secrets(rule) if {
	groups := to_set(rule.apiGroups)
	verbs := to_set(rule.verbs)

	# Match any of the three canonical core-group spellings.
	some g in groups
	g in {"", "core", "*"}

	# Match secrets, secrets subresources, or the resource wildcard.
	some r in to_set(rule.resources)
	resource_is_secrets(r)

	count(verbs) > 0
}

# rule_is_wildcard is true when any of apiGroups, resources, or verbs contains
# the RBAC "*" wildcard (grants more than the least-privilege baseline allows).
rule_is_wildcard(rule) if {
	"*" in to_set(rule.apiGroups)
}

rule_is_wildcard(rule) if {
	"*" in to_set(rule.resources)
}

rule_is_wildcard(rule) if {
	"*" in to_set(rule.verbs)
}

deny contains msg if {
	is_rbac_role
	some rule in input.rules
	rule_grants_secrets(rule)
	msg := sprintf(
		"%s/%s grants %s access to Secrets (apiGroups=%v resources=%v verbs=%v); least-privilege forbids it",
		[input.kind, input.metadata.name, scope_label, rule.apiGroups, rule.resources, rule.verbs],
	)
}

deny contains msg if {
	is_rbac_role
	some rule in input.rules
	rule_is_wildcard(rule)
	msg := sprintf(
		"%s/%s (%s) uses an RBAC wildcard (apiGroups=%v resources=%v verbs=%v); least-privilege forbids \"*\"",
		[input.kind, input.metadata.name, scope_label, rule.apiGroups, rule.resources, rule.verbs],
	)
}
