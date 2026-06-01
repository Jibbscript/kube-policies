# Network-posture gate (NET-WU-20, NIST SC-7 boundary protection / CIS 5.3.2).
#
# Regression guard for the P4 network-segmentation chart: a rendered
# kube-policies install MUST ship a fail-closed network boundary. The rules
# split by conftest evaluation shape, exactly as sa.token (per-doc) and
# sa.shared (--combine) do:
#
#   PER-DOCUMENT (conftest test --namespace network.posture):
#     `input` is a single rendered object. Two guards run here:
#       1. PSA-restricted Namespace: IF a Namespace object is present it MUST
#          carry pod-security.kubernetes.io/{enforce,audit,warn}: restricted.
#       2. No plaintext inter-service URL: a control-plane env var
#          (POLICY_MANAGER_URL / _INTERNAL_URL / _STREAM_URL) pointing at a
#          kube-policies service over http:// is denied. Scoped to those exact
#          control-plane keys so the legitimately-plaintext *_METRICS_URL
#          values (CRY-WU-08, http by default) do NOT false-positive.
#
#   CROSS-DOCUMENT (conftest test --combine --namespace network.posture):
#     `input` is the array of all docs ({path, contents}). Set-level existence
#     checks run here — "a default-deny exists across the doc set" is inherently
#     a combine assertion (mirrors sa_token_shared.rego):
#       3. Default-deny exists: some NetworkPolicy with podSelector == {} whose
#          policyTypes contains BOTH Ingress and Egress. This is the keystone —
#          removing the default-deny template MUST fail the build.
#       4. Per-component ingress NetworkPolicies exist for the webhook (:8443),
#          policy-manager (:8080), and metrics scraping. Dropping any one is a
#          segmentation regression.
#
# Under --combine the per-document rules are no-ops: `input.kind` on an array is
# undefined (not an error), and `input.spec`/`input.metadata` likewise. Under a
# per-document run the combine rules are no-ops: `some doc in input` iterates an
# object's keys, so `doc.contents.kind` is undefined and the comprehensions stay
# empty. No rule raises eval_conflict_error in either mode.
package network.posture

import rego.v1

# ---------------------------------------------------------------------------
# PER-DOCUMENT rule 1 — PSA-restricted Namespace.
# ---------------------------------------------------------------------------

is_namespace if {
	input.kind == "Namespace"
}

# _psa_levels is the set of pod-security.kubernetes.io label suffixes that must
# all be present and set to "restricted" on a shipped Namespace.
_psa_modes := {"enforce", "audit", "warn"}

deny contains msg if {
	is_namespace
	some mode in _psa_modes
	label := sprintf("pod-security.kubernetes.io/%s", [mode])
	object.get(input.metadata.labels, label, "") != "restricted"
	msg := sprintf(
		"Namespace/%s is missing label %s: restricted (got %q); PSA-restricted is required (NET-WU-20, CIS 5.3.2 / Pod Security Admission)",
		[input.metadata.name, label, object.get(input.metadata.labels, label, "")],
	)
}

# ---------------------------------------------------------------------------
# PER-DOCUMENT rule 2 — no plaintext inter-service control-plane URL.
# ---------------------------------------------------------------------------

# _control_plane_url_keys are the env var names that carry kube-policies
# control-plane (API / decisions / SSE-stream) endpoints. These MUST be https://
# (TLS shipped in P2: policy-manager TLS 1.3, CRY-WU-05/07). The *_METRICS_URL
# keys are deliberately excluded — they are http:// by default (CRY-WU-08) and
# would otherwise false-positive this rule.
_control_plane_url_keys := {
	"POLICY_MANAGER_URL",
	"POLICY_MANAGER_INTERNAL_URL",
	"POLICY_MANAGER_STREAM_URL",
}

# _is_workload is true for the object kinds that carry a pod template with env.
_is_workload if {
	input.kind == "Deployment"
}

_is_workload if {
	input.kind == "DaemonSet"
}

_is_workload if {
	input.kind == "StatefulSet"
}

deny contains msg if {
	_is_workload
	some container in input.spec.template.spec.containers
	some e in container.env
	e.name in _control_plane_url_keys
	startswith(e.value, "http://")
	msg := sprintf(
		"%s/%s container %q env %s is plaintext http:// (%q); inter-service control-plane traffic must be https:// (NET-WU-20, NIST SC-8)",
		[input.kind, input.metadata.name, container.name, e.name, e.value],
	)
}

# ---------------------------------------------------------------------------
# PER-DOCUMENT rule 2b — no unscoped allow-all-on-port NetworkPolicy rule.
# An ingress rule that sets `ports` but omits (or empties) `from` matches EVERY
# source on those ports — allow-all-on-port, which silently defeats the
# default-deny baseline. Likewise an egress rule with `ports` and no `to`. Every
# kube-policies allow rule MUST scope its peers (the fail-closed contract the
# templates document). Scoped by the app.kubernetes.io/name label so it only
# guards this chart's policies. (Security-review HIGH finding; NET-WU-20, SC-7.)
# ---------------------------------------------------------------------------

_is_kube_policies_np if {
	input.kind == "NetworkPolicy"
	object.get(input.metadata.labels, "app.kubernetes.io/name", "") == "kube-policies"
}

# _has_peers is true when rule[key] (from/to) holds at least one peer.
_has_peers(rule, key) if {
	count(object.get(rule, key, [])) > 0
}

deny contains msg if {
	_is_kube_policies_np
	some rule in input.spec.ingress
	count(rule.ports) > 0
	not _has_peers(rule, "from")
	msg := sprintf(
		"NetworkPolicy/%s has an unscoped ingress rule (ports set, empty/absent `from`): allow-all-on-port, not fail-closed (NET-WU-20, NIST SC-7)",
		[input.metadata.name],
	)
}

deny contains msg if {
	_is_kube_policies_np
	some rule in input.spec.egress
	count(rule.ports) > 0
	not _has_peers(rule, "to")
	msg := sprintf(
		"NetworkPolicy/%s has an unscoped egress rule (ports set, empty/absent `to`): allow-all-on-port, not fail-closed (NET-WU-20, NIST SC-7)",
		[input.metadata.name],
	)
}

# ---------------------------------------------------------------------------
# CROSS-DOCUMENT rule 3 — default-deny NetworkPolicy exists (--combine).
# ---------------------------------------------------------------------------

# _network_policies is the set of NetworkPolicy contents across the combined
# input. Defined as a comprehension so it is simply empty under a per-document
# run (where `some doc in input` iterates object keys, not documents).
_network_policies contains np if {
	some doc in input
	doc.contents.kind == "NetworkPolicy"
	np := doc.contents
}

# _has_default_deny is true when some NetworkPolicy selects all pods
# (podSelector == {}) and applies to BOTH Ingress and Egress — the fail-closed
# baseline every other (allow) policy layers on top of.
_has_default_deny if {
	some np in _network_policies
	np.spec.podSelector == {}
	types := {t | some t in np.spec.policyTypes}
	"Ingress" in types
	"Egress" in types
}

# _combine_active is true only under `conftest --combine`, where input is the
# array of documents. It gates the existence checks so they do NOT fire (as
# false negatives) during a per-document run where input is a single object.
_combine_active if {
	is_array(input)
	count(input) > 0
}

deny contains msg if {
	_combine_active
	not _has_default_deny
	msg := "no default-deny NetworkPolicy found (podSelector: {} with policyTypes [Ingress, Egress]); the fail-closed network baseline is missing (NET-WU-20, NIST SC-7 / CIS 5.3.2)"
}

# ---------------------------------------------------------------------------
# CROSS-DOCUMENT rule 4 — per-component ingress NetworkPolicies exist (--combine).
# ---------------------------------------------------------------------------

# _np_allows_ingress_port is true when NetworkPolicy np labelled for `component`
# admits Ingress on `port`. Confirms the component's listener is reachable
# through the segmentation boundary rather than being orphaned by default-deny.
_np_allows_ingress_port(component, port) if {
	some np in _network_policies
	np.metadata.labels["app.kubernetes.io/component"] == component
	"Ingress" in {t | some t in np.spec.policyTypes}
	some rule in np.spec.ingress
	some p in rule.ports
	p.port == port
}

# Expected per-component ingress listeners (component -> port):
#   admission-webhook : 8443 (webhook TLS) and 9090 (metrics scrape)
#   policy-manager    : 8080 (decisions API) and 9091 (metrics scrape)
_expected_ingress := [
	{"component": "admission-webhook", "port": 8443, "what": "admission webhook (TLS)"},
	{"component": "admission-webhook", "port": 9090, "what": "webhook metrics scrape"},
	{"component": "policy-manager", "port": 8080, "what": "policy-manager decisions API"},
	{"component": "policy-manager", "port": 9091, "what": "policy-manager metrics scrape"},
]

deny contains msg if {
	_combine_active
	some want in _expected_ingress
	not _np_allows_ingress_port(want.component, want.port)
	msg := sprintf(
		"missing ingress NetworkPolicy for %s on port %d (%s); per-component segmentation is incomplete (NET-WU-20, NIST SC-7)",
		[want.component, want.port, want.what],
	)
}
