package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// evalScoped enables policy p and evaluates a single object against ONLY that
// policy (no bundled defaults bleed in), so each pack's rules are tested in
// isolation. evalObject is defined in podspec_lib_test.go.
func evalScoped(t *testing.T, p *Policy, group, version, kind string, raw string) *EvaluationResult {
	t.Helper()
	p.Enabled = true
	eng, err := NewEvaluatorForPolicy(p, &config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	require.NoError(t, err)
	return evalObject(t, eng, group, version, kind, []byte(raw))
}

type ruleCase struct {
	name        string
	kind        string
	group       string
	raw         string
	wantAllowed bool
	wantRule    string // rule expected to fire when denied
}

// runRuleCases evaluates each case against a freshly-constructed policy so
// per-test parameter mutation never leaks between cases.
func runRuleCases(t *testing.T, ctor func() *Policy, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version := "v1"
			res := evalScoped(t, ctor(), tc.group, version, tc.kind, tc.raw)
			assert.Equalf(t, tc.wantAllowed, res.Allowed,
				"verdict mismatch; violations=%+v", res.Violations)
			if tc.wantAllowed {
				assert.Empty(t, res.Violations)
				return
			}
			fired := firedRuleIDs(res)
			assert.Truef(t, fired[tc.wantRule], "expected rule %q to fire; fired=%v", tc.wantRule, fired)
			for _, v := range res.Violations {
				assert.NotEmpty(t, v.Path, "violation %s has empty path", v.RuleID)
				assert.NotEmpty(t, v.Message, "violation %s has empty message", v.RuleID)
			}
		})
	}
}

func TestPSSBaseline(t *testing.T) {
	runRuleCases(t, pssBaselinePolicy, []ruleCase{
		{
			name: "hostNetwork denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"hostNetwork":true,"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: false, wantRule: "deny-host-namespaces",
		},
		{
			name: "hostPID via Deployment denied", kind: "Deployment", group: "apps",
			raw:         `{"kind":"Deployment","metadata":{"name":"d","namespace":"app"},"spec":{"template":{"spec":{"hostPID":true,"containers":[{"name":"c","image":"nginx:1"}]}}}}`,
			wantAllowed: false, wantRule: "deny-host-namespaces",
		},
		{
			name: "no host namespaces allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: true,
		},
		{
			name: "SYS_ADMIN capability denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","securityContext":{"capabilities":{"add":["SYS_ADMIN"]}}}]}}`,
			wantAllowed: false, wantRule: "restrict-capabilities",
		},
		{
			name: "NET_RAW on initContainer denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"initContainers":[{"name":"i","image":"busybox:1","securityContext":{"capabilities":{"add":["NET_RAW"]}}}],"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: false, wantRule: "restrict-capabilities",
		},
		{
			name: "NET_BIND_SERVICE allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","securityContext":{"capabilities":{"add":["NET_BIND_SERVICE"]}}}]}}`,
			wantAllowed: true,
		},
		{
			name: "hostPort denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","ports":[{"containerPort":8080,"hostPort":8080}]}]}}`,
			wantAllowed: false, wantRule: "deny-host-port",
		},
		{
			name: "containerPort only allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","ports":[{"containerPort":8080}]}]}}`,
			wantAllowed: true,
		},
		{
			name: "seccomp Unconfined denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"securityContext":{"seccompProfile":{"type":"Unconfined"}},"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: false, wantRule: "seccomp-not-unconfined",
		},
		{
			name: "seccomp RuntimeDefault allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: true,
		},
		{
			name: "unsafe sysctl denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"securityContext":{"sysctls":[{"name":"kernel.msgmax","value":"65536"}]},"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: false, wantRule: "deny-unsafe-sysctls",
		},
		{
			name: "safe sysctl allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"securityContext":{"sysctls":[{"name":"net.ipv4.tcp_syncookies","value":"1"}]},"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: true,
		},
		{
			name: "apparmor unconfined annotation denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app","annotations":{"container.apparmor.security.beta.kubernetes.io/c":"unconfined"}},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: false, wantRule: "deny-apparmor-unconfined",
		},
		{
			name: "apparmor field unconfined denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","securityContext":{"appArmorProfile":{"type":"Unconfined"}}}]}}`,
			wantAllowed: false, wantRule: "deny-apparmor-unconfined",
		},
	})
}

func TestPSSRestricted(t *testing.T) {
	runRuleCases(t, pssRestrictedPolicy, []ruleCase{
		{
			name: "missing allowPrivilegeEscalation denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","securityContext":{"runAsNonRoot":true,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}`,
			wantAllowed: false, wantRule: "require-no-privilege-escalation",
		},
		{
			name: "initContainer missing allowPrivilegeEscalation denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"initContainers":[{"name":"i","image":"busybox:1","securityContext":{"runAsNonRoot":true,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}],"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}`,
			wantAllowed: false, wantRule: "require-no-privilege-escalation",
		},
		{
			name: "missing drop ALL denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"readOnlyRootFilesystem":true}}]}}`,
			wantAllowed: false, wantRule: "require-drop-all-capabilities",
		},
		{
			name: "writable rootfs denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"capabilities":{"drop":["ALL"]}}}]}}`,
			wantAllowed: false, wantRule: "require-readonly-rootfs",
		},
		{
			name: "runAsUser 0 denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"readOnlyRootFilesystem":true,"runAsUser":0,"capabilities":{"drop":["ALL"]}}}]}}`,
			wantAllowed: false, wantRule: "require-run-as-nonroot",
		},
		{
			name: "no runAsNonRoot anywhere denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}`,
			wantAllowed: false, wantRule: "require-run-as-nonroot",
		},
		{
			name: "pod-level runAsNonRoot covers containers", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"securityContext":{"runAsNonRoot":true},"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}`,
			wantAllowed: true,
		},
		{
			name: "nfs volume denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"volumes":[{"name":"v","nfs":{"server":"10.0.0.1","path":"/x"}}],"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}`,
			wantAllowed: false, wantRule: "restrict-volume-types",
		},
		{
			name: "fully hardened pod allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"volumes":[{"name":"v","emptyDir":{}}],"containers":[{"name":"c","image":"nginx:1","securityContext":{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}`,
			wantAllowed: true,
		},
	})
}

func TestNSAHardening(t *testing.T) {
	runRuleCases(t, nsaHardeningPolicy, []ruleCase{
		{
			name: "missing memory limit denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"automountServiceAccountToken":false,"containers":[{"name":"c","image":"nginx:1","resources":{"requests":{"cpu":"100m","memory":"64Mi"},"limits":{"cpu":"200m"}}}]}}`,
			wantAllowed: false, wantRule: "require-resource-limits",
		},
		{
			name: "full resources allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"automountServiceAccountToken":false,"containers":[{"name":"c","image":"nginx:1","resources":{"requests":{"cpu":"100m","memory":"64Mi"},"limits":{"cpu":"200m","memory":"128Mi"}}}]}}`,
			wantAllowed: true,
		},
		{
			name: "automount unset denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","resources":{"requests":{"cpu":"100m","memory":"64Mi"},"limits":{"cpu":"200m","memory":"128Mi"}}}]}}`,
			wantAllowed: false, wantRule: "require-automount-token-disabled",
		},
		{
			name: "automount opt-in annotation allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app","annotations":{"policy.kube-policies.io/allow-automount-token":"true"}},"spec":{"containers":[{"name":"c","image":"nginx:1","resources":{"requests":{"cpu":"100m","memory":"64Mi"},"limits":{"cpu":"200m","memory":"128Mi"}}}]}}`,
			wantAllowed: true,
		},
	})
}

func TestGovernanceBaseline(t *testing.T) {
	runRuleCases(t, governanceBaselinePolicy, []ruleCase{
		{
			name: "missing owner label denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app","labels":{"app.kubernetes.io/name":"x","data-classification":"low"}},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: false, wantRule: "require-labels",
		},
		{
			name: "default namespace denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"default","labels":{"app.kubernetes.io/name":"x","owner":"team","data-classification":"low"}},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: false, wantRule: "deny-default-namespace",
		},
		{
			name: "fully labelled app-namespace pod allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app","labels":{"app.kubernetes.io/name":"x","owner":"team","data-classification":"low"}},"spec":{"containers":[{"name":"c","image":"nginx:1"}]}}`,
			wantAllowed: true,
		},
	})
}

// TestImageProvenance_RegistryParameterized proves POL-WU-13: the registry
// allowlist is read from policy parameters, not hardcoded, and traverses
// workload controllers (POL-WU-01).
func TestImageProvenance_RegistryParameterized(t *testing.T) {
	mk := func() *Policy {
		p := imageProvenancePolicy()
		p.Parameters = map[string]string{"allowedRegistries": "registry.internal/"}
		return p
	}
	runRuleCases(t, mk, []ruleCase{
		{
			name: "untrusted registry denied (custom allowlist)", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"docker.io/evil@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}}`,
			wantAllowed: false, wantRule: "allowed-registries",
		},
		{
			name: "trusted registry digest allowed (custom allowlist)", kind: "Deployment", group: "apps",
			raw:         `{"kind":"Deployment","metadata":{"name":"d","namespace":"app"},"spec":{"template":{"spec":{"containers":[{"name":"c","image":"registry.internal/app@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}}}}`,
			wantAllowed: true,
		},
		{
			name: "controller image without digest denied", kind: "Deployment", group: "apps",
			raw:         `{"kind":"Deployment","metadata":{"name":"d","namespace":"app"},"spec":{"template":{"spec":{"containers":[{"name":"c","image":"registry.internal/app:1.0.0"}]}}}}`,
			wantAllowed: false, wantRule: "require-image-digest",
		},
	})
}
