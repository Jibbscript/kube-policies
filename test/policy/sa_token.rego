# ServiceAccount token least-privilege gate (IAM-WU-17).
#
# Two concerns, two packages:
#
#   sa.token  — per-document: every ServiceAccount the chart renders MUST set
#               automountServiceAccountToken: false (IAM-WU-10, CIS 5.1.5/5.1.6).
#               The settled chart renders 3 SAs, all with the field false.
#
#   sa.shared — cross-document (conftest --combine): the admission-webhook and
#               policy-manager components MUST NOT share one ServiceAccount
#               (IAM-WU-08/09 split them into distinct least-privilege SAs).
#
# Both packages null-guard input.kind so comment-only / empty documents are
# skipped instead of raising an evaluation error.

package sa.token

import rego.v1

is_serviceaccount if {
	input.kind == "ServiceAccount"
}

# deny when a ServiceAccount does not explicitly disable token automounting.
# The `!= false` form catches both an explicit `true` and an absent/null field
# (the cluster default, which mounts the token). object.get resolves the field
# to `null` when absent BEFORE comparing — a bare `input.x != false` reference
# is undefined (not true) on a missing key, which would silently pass the
# cluster-default-on case this gate exists to catch. Equality against the
# literal boolean `false` is the only passing state.
deny contains msg if {
	is_serviceaccount
	automount := object.get(input, "automountServiceAccountToken", null)
	automount != false
	msg := sprintf(
		"ServiceAccount/%s must set automountServiceAccountToken: false (got %v); CIS 5.1.5/5.1.6, IAM-WU-10",
		[input.metadata.name, automount],
	)
}

# The cross-document shared-ServiceAccount check (package sa.shared) lives in
# sa_token_shared.rego: Rego forbids two `package` declarations in one file, so
# the --combine-only rule is split into a sibling file under this same dir.
