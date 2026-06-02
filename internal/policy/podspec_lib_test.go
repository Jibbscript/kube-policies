package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// evalObject boots the real engine (bundled defaults loaded) and evaluates a
// single admitted object of the given group/version/kind. It is the shared
// harness for the podspec-library and kind-routing tests.
func evalObject(t *testing.T, eng *Engine, group, version, kind string, raw []byte) *EvaluationResult {
	t.Helper()
	res, err := eng.Evaluate(context.Background(), &EvaluationRequest{
		AdmissionRequest: &admissionv1.AdmissionRequest{
			UID:       types.UID("podspec-" + kind),
			Kind:      metav1.GroupVersionKind{Group: group, Version: version, Kind: kind},
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
		},
		Operation: "validate",
	})
	require.NoError(t, err)
	return res
}

func newDefaultEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := NewEngine(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	require.NoError(t, err)
	return eng
}

func firedRuleIDs(res *EvaluationResult) map[string]bool {
	out := make(map[string]bool, len(res.Violations))
	for _, v := range res.Violations {
		out[v.RuleID] = true
	}
	return out
}

// TestPodSpecLib_WorkloadControllerTraversal is the POL-WU-01/POL-WU-02 exit
// proof: a privileged container nested inside a workload controller's pod
// template — the normal way workloads ship — is now denied. Before the shared
// podspec library, the bundled rules read input.object.spec.containers only and
// these all sailed through admission.
func TestPodSpecLib_WorkloadControllerTraversal(t *testing.T) {
	eng := newDefaultEngine(t)

	cases := []struct {
		name       string
		group      string
		kind       string
		raw        string
		wantRuleID string
	}{
		{
			name:  "privileged Deployment container",
			group: "apps", kind: "Deployment",
			raw: `{
				"apiVersion":"apps/v1","kind":"Deployment",
				"metadata":{"name":"d","namespace":"app"},
				"spec":{"template":{"spec":{"containers":[
					{"name":"c","image":"nginx:1.25.3","securityContext":{"privileged":true,"runAsNonRoot":true,"allowPrivilegeEscalation":false}}
				]}}}
			}`,
			wantRuleID: "no-privileged-containers",
		},
		{
			name:  "hostPath StatefulSet volume",
			group: "apps", kind: "StatefulSet",
			raw: `{
				"apiVersion":"apps/v1","kind":"StatefulSet",
				"metadata":{"name":"s","namespace":"app"},
				"spec":{"template":{"spec":{
					"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}],
					"volumes":[{"name":"h","hostPath":{"path":"/var/run/docker.sock"}}]
				}}}
			}`,
			wantRuleID: "no-host-path-volumes",
		},
		{
			name:  "latest tag DaemonSet image",
			group: "apps", kind: "DaemonSet",
			raw: `{
				"apiVersion":"apps/v1","kind":"DaemonSet",
				"metadata":{"name":"ds","namespace":"app"},
				"spec":{"template":{"spec":{"containers":[
					{"name":"c","image":"nginx:latest","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}
				]}}}
			}`,
			wantRuleID: "no-latest-image-tag",
		},
		{
			name:  "missing securityContext CronJob",
			group: "batch", kind: "CronJob",
			raw: `{
				"apiVersion":"batch/v1","kind":"CronJob",
				"metadata":{"name":"cj","namespace":"app"},
				"spec":{"jobTemplate":{"spec":{"template":{"spec":{"containers":[
					{"name":"c","image":"nginx:1.25.3"}
				]}}}}}
			}`,
			wantRuleID: "required-security-context",
		},
		{
			name:  "privileged initContainer in bare Pod",
			group: "", kind: "Pod",
			raw: `{
				"apiVersion":"v1","kind":"Pod",
				"metadata":{"name":"p","namespace":"app"},
				"spec":{
					"initContainers":[{"name":"init","image":"busybox:1.36","securityContext":{"privileged":true,"runAsNonRoot":true,"allowPrivilegeEscalation":false}}],
					"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]
				}
			}`,
			wantRuleID: "no-privileged-containers",
		},
		{
			name:  "privileged ephemeralContainer in bare Pod",
			group: "", kind: "Pod",
			raw: `{
				"apiVersion":"v1","kind":"Pod",
				"metadata":{"name":"p","namespace":"app"},
				"spec":{
					"ephemeralContainers":[{"name":"debug","image":"busybox:1.36","securityContext":{"privileged":true}}],
					"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]
				}
			}`,
			wantRuleID: "no-privileged-containers",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version := "v1"
			res := evalObject(t, eng, tc.group, version, tc.kind, []byte(tc.raw))
			assert.False(t, res.Allowed, "expected deny; violations=%+v", res.Violations)
			fired := firedRuleIDs(res)
			assert.True(t, fired[tc.wantRuleID],
				"expected rule %q to fire for %s; fired=%v", tc.wantRuleID, tc.name, fired)
			// Every violation must carry a kind-correct, non-empty path.
			for _, v := range res.Violations {
				assert.NotEmpty(t, v.Path, "violation %s has empty path", v.RuleID)
			}
		})
	}
}

// TestPodSpecLib_CompliantControllerAllowed proves the library does not
// over-block: a fully compliant Deployment (init + main containers hardened) is
// admitted.
func TestPodSpecLib_CompliantControllerAllowed(t *testing.T) {
	eng := newDefaultEngine(t)
	raw := `{
		"apiVersion":"apps/v1","kind":"Deployment",
		"metadata":{"name":"d","namespace":"app"},
		"spec":{"template":{"spec":{
			"initContainers":[{"name":"init","image":"busybox:1.36.1","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}],
			"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]
		}}}
	}`
	res := evalObject(t, eng, "apps", "v1", "Deployment", []byte(raw))
	assert.True(t, res.Allowed, "compliant Deployment should be admitted; violations=%+v", res.Violations)
	assert.Empty(t, res.Violations)
}

// TestKindRouting_PodRulesSkipNonPodKinds is the POL-WU-21 proof: a pod-shaped
// rule does not fire — and, critically, does not error and fail-close the whole
// request — when evaluating a non-pod kind such as a ClusterRole.
func TestKindRouting_PodRulesSkipNonPodKinds(t *testing.T) {
	eng := newDefaultEngine(t)

	// A ClusterRole granting wildcard verbs. The bundled pod rules must not
	// evaluate it at all; with no non-pod rules loaded yet, the verdict is allow.
	clusterRole := `{
		"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole",
		"metadata":{"name":"too-broad"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]
	}`
	res := evalObject(t, eng, "rbac.authorization.k8s.io", "v1", "ClusterRole", []byte(clusterRole))
	assert.True(t, res.Allowed,
		"pod rules must be skipped for ClusterRole (POL-WU-21); violations=%+v", res.Violations)
	assert.Empty(t, res.Violations)
}

// TestRuleAppliesToKind unit-tests the routing predicate directly across the
// webhook-intercepted kinds.
func TestRuleAppliesToKind(t *testing.T) {
	podRule := &Rule{ID: "pod-rule", TargetKinds: podWorkloadKinds}
	rbacRule := &Rule{ID: "rbac-rule", TargetKinds: []string{"Role", "ClusterRole"}}
	anyRule := &Rule{ID: "any-rule"} // no TargetKinds → applies to all

	cases := []struct {
		rule *Rule
		kind string
		want bool
	}{
		{podRule, "Pod", true},
		{podRule, "Deployment", true},
		{podRule, "CronJob", true},
		{podRule, "ClusterRole", false},
		{podRule, "NetworkPolicy", false},
		{rbacRule, "ClusterRole", true},
		{rbacRule, "clusterrole", true}, // case-insensitive
		{rbacRule, "Pod", false},
		{anyRule, "Pod", true},
		{anyRule, "Secret", true},
		{podRule, "", true}, // empty kind matches everything
	}
	for _, tc := range cases {
		got := ruleAppliesToKind(tc.rule, tc.kind)
		assert.Equalf(t, tc.want, got, "ruleAppliesToKind(%s, %q)", tc.rule.ID, tc.kind)
	}
}
