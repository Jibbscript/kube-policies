package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// rule_coverage_test.go is the per-rule golden coverage harness (POL-WU-25).
//
// ruleCoverage holds, for EVERY shipped rule, a deny fixture (must be rejected
// with that rule firing) and an allow fixture (must be admitted). The test then
// asserts the registry's key set equals the engine's shipped-rule set, so adding
// a rule without a fixture FAILS CI and the failure message enumerates the gap —
// satisfying "a coverage report enumerates which rules lack fixtures" and "a
// deliberately broken rule causes the job to fail."

// hardenedContainer passes every pss-restricted rule, so an allow fixture (or a
// deny fixture that breaks exactly one field) is built from it.
const hardenedContainer = `{"name":"c","image":"nginx:1.25.3","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}`

func pod(spec string) string {
	return `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":` + spec + `}`
}

type coverageFixture struct {
	policy   func() *Policy
	group    string
	kind     string
	deny     string // must be DENIED (or for mutation rules, must PRODUCE patches)
	allow    string // must be ALLOWED (or for mutation rules, NO patches)
	mutation bool   // mutation rules never deny; coverage is patches vs no-patches
}

var ruleCoverage = map[string]coverageFixture{
	// security-baseline
	"no-privileged-containers": {policy: securityBaselineCtor, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"privileged":true}}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}`)},
	"no-host-path-volumes": {policy: securityBaselineCtor, kind: "Pod",
		deny:  pod(`{"volumes":[{"name":"h","hostPath":{"path":"/"}}],"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}`)},
	"no-latest-image-tag": {policy: securityBaselineCtor, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:latest","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}`)},
	"required-security-context": {policy: securityBaselineCtor, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1.25.3"}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}`)},

	// image-provenance (default param allowlist: ghcr.io/jibbscript/)
	"allowed-registries": {policy: imageProvenancePolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"docker.io/evil@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"ghcr.io/jibbscript/app@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}`)},
	"require-image-digest": {policy: imageProvenancePolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"ghcr.io/jibbscript/app:1.0.0"}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"ghcr.io/jibbscript/app@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}`)},

	// pss-baseline
	"deny-host-namespaces": {policy: pssBaselinePolicy, kind: "Pod",
		deny:  pod(`{"hostNetwork":true,"containers":[{"name":"c","image":"nginx:1"}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"nginx:1"}]}`)},
	"restrict-capabilities": {policy: pssBaselinePolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1","securityContext":{"capabilities":{"add":["SYS_ADMIN"]}}}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"nginx:1","securityContext":{"capabilities":{"add":["NET_BIND_SERVICE"]}}}]}`)},
	"deny-host-port": {policy: pssBaselinePolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1","ports":[{"hostPort":80}]}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"nginx:1","ports":[{"containerPort":80}]}]}`)},
	"seccomp-not-unconfined": {policy: pssBaselinePolicy, kind: "Pod",
		deny:  pod(`{"securityContext":{"seccompProfile":{"type":"Unconfined"}},"containers":[{"name":"c","image":"nginx:1"}]}`),
		allow: pod(`{"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"c","image":"nginx:1"}]}`)},
	"deny-unsafe-sysctls": {policy: pssBaselinePolicy, kind: "Pod",
		deny:  pod(`{"securityContext":{"sysctls":[{"name":"kernel.msgmax","value":"1"}]},"containers":[{"name":"c","image":"nginx:1"}]}`),
		allow: pod(`{"securityContext":{"sysctls":[{"name":"net.ipv4.tcp_syncookies","value":"1"}]},"containers":[{"name":"c","image":"nginx:1"}]}`)},
	"deny-apparmor-unconfined": {policy: pssBaselinePolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1","securityContext":{"appArmorProfile":{"type":"Unconfined"}}}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"nginx:1","securityContext":{"appArmorProfile":{"type":"RuntimeDefault"}}}]}`)},

	// pss-restricted (allow = fully hardened; deny = one field broken)
	"require-no-privilege-escalation": {policy: pssRestrictedPolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1","securityContext":{"runAsNonRoot":true,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}`),
		allow: pod(`{"containers":[` + hardenedContainer + `]}`)},
	"require-drop-all-capabilities": {policy: pssRestrictedPolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"readOnlyRootFilesystem":true}}]}`),
		allow: pod(`{"containers":[` + hardenedContainer + `]}`)},
	"require-readonly-rootfs": {policy: pssRestrictedPolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"capabilities":{"drop":["ALL"]}}}]}`),
		allow: pod(`{"containers":[` + hardenedContainer + `]}`)},
	"require-run-as-nonroot": {policy: pssRestrictedPolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}`),
		allow: pod(`{"containers":[` + hardenedContainer + `]}`)},
	"restrict-volume-types": {policy: pssRestrictedPolicy, kind: "Pod",
		deny:  pod(`{"volumes":[{"name":"v","nfs":{"server":"1.1.1.1","path":"/x"}}],"containers":[` + hardenedContainer + `]}`),
		allow: pod(`{"volumes":[{"name":"v","emptyDir":{}}],"containers":[` + hardenedContainer + `]}`)},

	// nsa-hardening (allow must satisfy BOTH rules: resources + automount false)
	"require-resource-limits": {policy: nsaHardeningPolicy, kind: "Pod",
		deny:  pod(`{"automountServiceAccountToken":false,"containers":[{"name":"c","image":"nginx:1","resources":{"requests":{"cpu":"1","memory":"1Mi"},"limits":{"cpu":"1"}}}]}`),
		allow: pod(`{"automountServiceAccountToken":false,"containers":[{"name":"c","image":"nginx:1","resources":{"requests":{"cpu":"1","memory":"1Mi"},"limits":{"cpu":"1","memory":"1Mi"}}}]}`)},
	"require-automount-token-disabled": {policy: nsaHardeningPolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1","resources":{"requests":{"cpu":"1","memory":"1Mi"},"limits":{"cpu":"1","memory":"1Mi"}}}]}`),
		allow: pod(`{"automountServiceAccountToken":false,"containers":[{"name":"c","image":"nginx:1","resources":{"requests":{"cpu":"1","memory":"1Mi"},"limits":{"cpu":"1","memory":"1Mi"}}}]}`)},

	// governance-baseline (allow must satisfy BOTH: labels + non-default ns)
	"require-labels": {policy: governanceBaselinePolicy, kind: "Pod",
		deny:  `{"kind":"Pod","metadata":{"name":"p","namespace":"app","labels":{"app.kubernetes.io/name":"x"}},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`,
		allow: `{"kind":"Pod","metadata":{"name":"p","namespace":"app","labels":{"app.kubernetes.io/name":"x","owner":"t","data-classification":"low"}},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`},
	"deny-default-namespace": {policy: governanceBaselinePolicy, kind: "Pod",
		deny:  `{"kind":"Pod","metadata":{"name":"p","namespace":"default","labels":{"app.kubernetes.io/name":"x","owner":"t","data-classification":"low"}},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`,
		allow: `{"kind":"Pod","metadata":{"name":"p","namespace":"app","labels":{"app.kubernetes.io/name":"x","owner":"t","data-classification":"low"}},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`},

	// rbac-baseline
	"deny-wildcard-rbac": {policy: rbacBaselinePolicy, group: "rbac.authorization.k8s.io", kind: "ClusterRole",
		deny:  `{"kind":"ClusterRole","metadata":{"name":"x"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["*"]}]}`,
		allow: `{"kind":"ClusterRole","metadata":{"name":"x"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}`},
	"deny-dangerous-verbs": {policy: rbacBaselinePolicy, group: "rbac.authorization.k8s.io", kind: "Role",
		deny:  `{"kind":"Role","metadata":{"name":"x","namespace":"app"},"rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["roles"],"verbs":["escalate"]}]}`,
		allow: `{"kind":"Role","metadata":{"name":"x","namespace":"app"},"rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["get"]}]}`},
	"deny-cluster-admin-binding": {policy: rbacBaselinePolicy, group: "rbac.authorization.k8s.io", kind: "ClusterRoleBinding",
		deny:  `{"kind":"ClusterRoleBinding","metadata":{"name":"x"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"sa","namespace":"app"}]}`,
		allow: `{"kind":"ClusterRoleBinding","metadata":{"name":"x"},"roleRef":{"kind":"ClusterRole","name":"view"},"subjects":[{"kind":"ServiceAccount","name":"sa","namespace":"app"}]}`},
	"deny-broad-subject-binding": {policy: rbacBaselinePolicy, group: "rbac.authorization.k8s.io", kind: "RoleBinding",
		deny:  `{"kind":"RoleBinding","metadata":{"name":"x","namespace":"app"},"roleRef":{"kind":"Role","name":"v"},"subjects":[{"kind":"Group","name":"system:authenticated"}]}`,
		allow: `{"kind":"RoleBinding","metadata":{"name":"x","namespace":"app"},"roleRef":{"kind":"Role","name":"v"},"subjects":[{"kind":"ServiceAccount","name":"sa","namespace":"app"}]}`},

	// secrets-baseline
	"deny-secret-env": {policy: secretsBaselinePolicy, kind: "Pod",
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1","env":[{"name":"P","valueFrom":{"secretKeyRef":{"name":"s","key":"k"}}}]}]}`),
		allow: pod(`{"containers":[{"name":"c","image":"nginx:1"}]}`)},
	"flag-configmap-sensitive": {policy: secretsBaselinePolicy, kind: "ConfigMap",
		deny:  `{"kind":"ConfigMap","metadata":{"name":"cm","namespace":"app"},"data":{"api_token":"x"}}`,
		allow: `{"kind":"ConfigMap","metadata":{"name":"cm","namespace":"app"},"data":{"log_level":"info"}}`},

	// network-baseline
	"deny-overly-broad-netpol": {policy: networkBaselinePolicy, group: "networking.k8s.io", kind: "NetworkPolicy",
		deny:  `{"kind":"NetworkPolicy","metadata":{"name":"n","namespace":"app"},"spec":{"podSelector":{},"ingress":[{}]}}`,
		allow: `{"kind":"NetworkPolicy","metadata":{"name":"n","namespace":"app"},"spec":{"podSelector":{},"policyTypes":["Ingress"]}}`},
	"ingress-require-tls-no-wildcard": {policy: networkBaselinePolicy, group: "networking.k8s.io", kind: "Ingress",
		deny:  `{"kind":"Ingress","metadata":{"name":"i","namespace":"app"},"spec":{"rules":[{"host":"a.example.com"}]}}`,
		allow: `{"kind":"Ingress","metadata":{"name":"i","namespace":"app"},"spec":{"tls":[{"hosts":["a.example.com"]}],"rules":[{"host":"a.example.com"}]}}`},

	// mutating-hardening (mutation: deny fixture -> patches; allow fixture -> none)
	"harden-pod-securitycontext": {policy: mutatingHardeningPolicy, kind: "Pod", mutation: true,
		deny:  pod(`{"containers":[{"name":"c","image":"nginx:1.25.3"}]}`),
		allow: pod(`{"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}},"automountServiceAccountToken":false,"containers":[` + hardenedContainer + `]}`)},
}

// securityBaselineCtor returns a fresh security-baseline policy (the bundled
// default) for the coverage harness.
func securityBaselineCtor() *Policy {
	eng, err := NewEngine(&config.PolicyConfig{}, zap.NewNop())
	if err != nil {
		panic(err)
	}
	return eng.policies["security-baseline"]
}

func TestPerRuleCoverage(t *testing.T) {
	eng := newDefaultEngine(t)
	shipped := make(map[string]bool)
	for _, p := range eng.ListPolicies() {
		for _, r := range p.Rules {
			shipped[r.ID] = true
		}
	}

	// Completeness: every shipped rule must have a fixture, and no fixture may
	// reference a rule that no longer ships. Failures name the offending rule.
	for id := range shipped {
		_, ok := ruleCoverage[id]
		assert.Truef(t, ok, "POL-WU-25 COVERAGE GAP: rule %q has no allow/deny fixture", id)
	}
	for id := range ruleCoverage {
		assert.Truef(t, shipped[id], "coverage fixture references unknown rule %q", id)
	}

	for id, f := range ruleCoverage {
		t.Run(id, func(t *testing.T) {
			denyRes := evalScoped(t, f.policy(), f.group, "v1", f.kind, f.deny)
			allowRes := evalScoped(t, f.policy(), f.group, "v1", f.kind, f.allow)
			if f.mutation {
				require.True(t, denyRes.Allowed, "mutation rule must not deny")
				assert.NotEmptyf(t, denyRes.Patches, "mutation deny fixture for %q must produce patches", id)
				assert.Emptyf(t, allowRes.Patches, "mutation allow fixture for %q must produce no patches", id)
				return
			}
			assert.Falsef(t, denyRes.Allowed, "deny fixture for %q must be rejected; violations=%+v", id, denyRes.Violations)
			assert.Truef(t, firedRuleIDs(denyRes)[id], "deny fixture for %q must fire rule %q; fired=%v", id, id, firedRuleIDs(denyRes))
			assert.Truef(t, allowRes.Allowed, "allow fixture for %q must be admitted; violations=%+v", id, allowRes.Violations)
		})
	}
}
