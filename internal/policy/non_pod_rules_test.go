package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRBACBaseline(t *testing.T) {
	const rbacGroup = "rbac.authorization.k8s.io"
	runRuleCases(t, rbacBaselinePolicy, []ruleCase{
		{
			name: "wildcard verbs ClusterRole denied", kind: "ClusterRole", group: rbacGroup,
			raw:         `{"kind":"ClusterRole","metadata":{"name":"x"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["*"]}]}`,
			wantAllowed: false, wantRule: "deny-wildcard-rbac",
		},
		{
			name: "wildcard resources ClusterRole denied", kind: "ClusterRole", group: rbacGroup,
			raw:         `{"kind":"ClusterRole","metadata":{"name":"x"},"rules":[{"apiGroups":[""],"resources":["*"],"verbs":["get"]}]}`,
			wantAllowed: false, wantRule: "deny-wildcard-rbac",
		},
		{
			name: "escalate verb Role denied", kind: "Role", group: rbacGroup,
			raw:         `{"kind":"Role","metadata":{"name":"x","namespace":"app"},"rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["roles"],"verbs":["escalate"]}]}`,
			wantAllowed: false, wantRule: "deny-dangerous-verbs",
		},
		{
			name: "least-privilege Role allowed", kind: "Role", group: rbacGroup,
			raw:         `{"kind":"Role","metadata":{"name":"x","namespace":"app"},"rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["get","list","watch"]}]}`,
			wantAllowed: true,
		},
		{
			name: "cluster-admin ClusterRoleBinding denied", kind: "ClusterRoleBinding", group: rbacGroup,
			raw:         `{"kind":"ClusterRoleBinding","metadata":{"name":"x"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"User","name":"alice"}]}`,
			wantAllowed: false, wantRule: "deny-cluster-admin-binding",
		},
		{
			name: "system:authenticated RoleBinding denied", kind: "RoleBinding", group: rbacGroup,
			raw:         `{"kind":"RoleBinding","metadata":{"name":"x","namespace":"app"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"viewer"},"subjects":[{"kind":"Group","name":"system:authenticated"}]}`,
			wantAllowed: false, wantRule: "deny-broad-subject-binding",
		},
		{
			name: "scoped RoleBinding to named SA allowed", kind: "RoleBinding", group: rbacGroup,
			raw:         `{"kind":"RoleBinding","metadata":{"name":"x","namespace":"app"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"viewer"},"subjects":[{"kind":"ServiceAccount","name":"app-sa","namespace":"app"}]}`,
			wantAllowed: true,
		},
	})
}

func TestSecretsBaseline(t *testing.T) {
	runRuleCases(t, secretsBaselinePolicy, []ruleCase{
		{
			name: "secretKeyRef env denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","env":[{"name":"PW","valueFrom":{"secretKeyRef":{"name":"s","key":"pw"}}}]}]}}`,
			wantAllowed: false, wantRule: "deny-secret-env",
		},
		{
			name: "envFrom secretRef denied", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"containers":[{"name":"c","image":"nginx:1","envFrom":[{"secretRef":{"name":"s"}}]}]}}`,
			wantAllowed: false, wantRule: "deny-secret-env",
		},
		{
			name: "secret mounted as file allowed", kind: "Pod",
			raw:         `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"volumes":[{"name":"s","secret":{"secretName":"s"}}],"containers":[{"name":"c","image":"nginx:1","volumeMounts":[{"name":"s","mountPath":"/etc/s"}]}]}}`,
			wantAllowed: true,
		},
		{
			name: "configmap with password key denied", kind: "ConfigMap",
			raw:         `{"kind":"ConfigMap","metadata":{"name":"cm","namespace":"app"},"data":{"db_password":"hunter2"}}`,
			wantAllowed: false, wantRule: "flag-configmap-sensitive",
		},
		{
			name: "benign configmap allowed", kind: "ConfigMap",
			raw:         `{"kind":"ConfigMap","metadata":{"name":"cm","namespace":"app"},"data":{"log_level":"info"}}`,
			wantAllowed: true,
		},
	})
}

func TestNetworkBaseline(t *testing.T) {
	const netGroup = "networking.k8s.io"
	runRuleCases(t, networkBaselinePolicy, []ruleCase{
		{
			name: "allow-all NetworkPolicy denied", kind: "NetworkPolicy", group: netGroup,
			raw:         `{"kind":"NetworkPolicy","metadata":{"name":"np","namespace":"app"},"spec":{"podSelector":{},"ingress":[{}],"policyTypes":["Ingress"]}}`,
			wantAllowed: false, wantRule: "deny-overly-broad-netpol",
		},
		{
			name: "default-deny NetworkPolicy allowed", kind: "NetworkPolicy", group: netGroup,
			raw:         `{"kind":"NetworkPolicy","metadata":{"name":"np","namespace":"app"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}}`,
			wantAllowed: true,
		},
		{
			name: "scoped allow-all is fine (non-empty selector)", kind: "NetworkPolicy", group: netGroup,
			raw:         `{"kind":"NetworkPolicy","metadata":{"name":"np","namespace":"app"},"spec":{"podSelector":{"matchLabels":{"app":"x"}},"ingress":[{}],"policyTypes":["Ingress"]}}`,
			wantAllowed: true,
		},
		{
			name: "ingress without TLS denied", kind: "Ingress", group: netGroup,
			raw:         `{"kind":"Ingress","metadata":{"name":"i","namespace":"app"},"spec":{"rules":[{"host":"app.example.com"}]}}`,
			wantAllowed: false, wantRule: "ingress-require-tls-no-wildcard",
		},
		{
			name: "ingress wildcard host denied", kind: "Ingress", group: netGroup,
			raw:         `{"kind":"Ingress","metadata":{"name":"i","namespace":"app"},"spec":{"tls":[{"hosts":["*.example.com"]}],"rules":[{"host":"*.example.com"}]}}`,
			wantAllowed: false, wantRule: "ingress-require-tls-no-wildcard",
		},
		{
			name: "ingress with TLS and explicit host allowed", kind: "Ingress", group: netGroup,
			raw:         `{"kind":"Ingress","metadata":{"name":"i","namespace":"app"},"spec":{"tls":[{"hosts":["app.example.com"],"secretName":"tls"}],"rules":[{"host":"app.example.com"}]}}`,
			wantAllowed: true,
		},
	})
}

// TestKindRouting_CrossPack is the end-to-end POL-WU-21 proof with REAL non-pod
// rules loaded alongside pod rules: a ClusterRole triggers only the RBAC rule
// (pod rules are skipped, not errored), and a privileged Pod triggers only the
// pod rule (RBAC rules are skipped). This is what prevents a pod rule from
// fail-closing every ClusterRole admission once both packs are active.
func TestKindRouting_CrossPack(t *testing.T) {
	eng := newDefaultEngine(t)
	for _, c := range []func() *Policy{pssBaselinePolicy, rbacBaselinePolicy} {
		p := c()
		p.Enabled = true
		require.NoError(t, eng.LoadPolicy(p))
	}

	// Wildcard ClusterRole: only the RBAC rule should fire.
	cr := `{"kind":"ClusterRole","metadata":{"name":"x"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`
	res := evalObject(t, eng, "rbac.authorization.k8s.io", "v1", "ClusterRole", []byte(cr))
	require.False(t, res.Allowed)
	fired := firedRuleIDs(res)
	assert.True(t, fired["deny-wildcard-rbac"], "RBAC rule must fire on ClusterRole")
	assert.False(t, fired["deny-host-namespaces"], "pod rule must NOT fire on ClusterRole")
	assert.False(t, fired["restrict-capabilities"], "pod rule must NOT fire on ClusterRole")

	// hostNetwork Pod: only the pod rule should fire.
	pod := `{"kind":"Pod","metadata":{"name":"p","namespace":"app"},"spec":{"hostNetwork":true,"containers":[{"name":"c","image":"nginx:1"}]}}`
	res2 := evalObject(t, eng, "", "v1", "Pod", []byte(pod))
	require.False(t, res2.Allowed)
	fired2 := firedRuleIDs(res2)
	assert.True(t, fired2["deny-host-namespaces"], "pod rule must fire on Pod")
	assert.False(t, fired2["deny-wildcard-rbac"], "RBAC rule must NOT fire on Pod")
	assert.False(t, fired2["deny-cluster-admin-binding"], "RBAC rule must NOT fire on Pod")
}
