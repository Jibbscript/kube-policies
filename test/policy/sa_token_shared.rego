# Cross-document shared-ServiceAccount gate (IAM-WU-17).
#
# Sibling of sa_token.rego (Rego forbids two `package` blocks in one file).
# Evaluated under `conftest test --combine`, where `input` is the array of all
# documents ({path, contents}) across the rendered files. Two rules:
#
#   1. Shared-SA regression: denies when the admission-webhook and
#      policy-manager Deployments' pod-template serviceAccountNames intersect —
#      i.e. both components resolve to at least one common SA name.
#      Uses a set-valued partial rule (component_sas) so a label collision
#      (two Deployments for one component with *different* SAs) never raises
#      eval_conflict_error; the intersection of both sets is what matters.
#
#   2. Label-drift guard: denies (fail-closed) when fewer than two expected
#      component-labeled Deployments are present across the combined input.
#      Dropping the app.kubernetes.io/component label silently disables rule 1;
#      this guard catches that evasion.
#
# Under a per-document (non --combine) run `input` is a single object, so
# `some doc in input` iterates nothing — both rules are no-ops with no errors.
package sa.shared

import rego.v1

# component_sas collects the set of serviceAccountNames used by all Deployments
# carrying a given app.kubernetes.io/component label value. Set-valued so
# multiple Deployments for the same component (each potentially with a different
# SA) don't produce eval_conflict_error.
component_sas(component) := {sa |
	some doc in input
	doc.contents.kind == "Deployment"
	doc.contents.metadata.labels["app.kubernetes.io/component"] == component
	sa := doc.contents.spec.template.spec.serviceAccountName
}

# _expected_components is the set of component labels the gate monitors.
# Adding a new privileged component here automatically enables the drift guard.
_expected_components := {"admission-webhook", "policy-manager"}

# _present_components collects every component label seen across all Deployments
# in the combined input.
_present_components := {c |
	some doc in input
	doc.contents.kind == "Deployment"
	c := doc.contents.metadata.labels["app.kubernetes.io/component"]
	c in _expected_components
}

# Rule 1 — shared SA regression guard.
deny contains msg if {
	shared := component_sas("admission-webhook") & component_sas("policy-manager")
	count(shared) > 0
	msg := sprintf(
		"admission-webhook and policy-manager Deployments share serviceAccountName(s) %v; IAM-WU-08/09 require distinct least-privilege ServiceAccounts",
		[shared],
	)
}

# Rule 2 — label-drift guard (fail-closed).
# If one of the monitored components is missing entirely from the combined input
# the shared-SA check above would silently pass (empty intersection of an empty
# set is always empty). Deny so that removing the component label is caught.
deny contains msg if {
	missing := _expected_components - _present_components
	count(missing) > 0
	msg := sprintf(
		"expected component-labeled Deployment(s) absent from combined input: %v; dropping app.kubernetes.io/component label evades the shared-SA check (IAM-WU-17)",
		[missing],
	)
}
