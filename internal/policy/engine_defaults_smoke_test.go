package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// TestDefaultPolicies_PlaygroundVerdicts exercises each of the 4 bundled
// default rules against a representative payload to verify the Rego
// authored in loadDefaultPolicies() honors the engine contract
// (`data.kube_policies.evaluate` returning {allowed, message, path}).
//
// This is the smoke test that closes acceptance criterion #11 for M1
// without depending on the web/ fixtures landing first; T5's
// bundled_defaults_test will tie the same checks to those JSON files.
func TestDefaultPolicies_PlaygroundVerdicts(t *testing.T) {
	engine, err := NewEngine(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	require.NoError(t, err)

	tests := []struct {
		name           string
		pod            map[string]any
		wantAllowed    bool
		wantRuleIDs    []string // rule IDs expected to fire (non-strict subset)
		wantSomeFireOn []string // any one of these rule IDs must fire (alternative)
	}{
		{
			name: "privileged-pod-denies",
			pod: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "p", "namespace": "default"},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "c",
							"image": "nginx:1.25",
							"securityContext": map[string]any{
								"privileged":             true,
								"runAsNonRoot":           true,
								"allowPrivilegeEscalation": false,
							},
						},
					},
				},
			},
			wantAllowed: false,
			wantRuleIDs: []string{"no-privileged-containers"},
		},
		{
			name: "hostpath-pod-denies",
			pod: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "p", "namespace": "default"},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "c",
							"image": "nginx:1.25",
							"securityContext": map[string]any{
								"runAsNonRoot":             true,
								"allowPrivilegeEscalation": false,
							},
						},
					},
					"volumes": []any{
						map[string]any{
							"name":     "host",
							"hostPath": map[string]any{"path": "/var/run/docker.sock"},
						},
					},
				},
			},
			wantAllowed: false,
			wantRuleIDs: []string{"no-host-path-volumes"},
		},
		{
			name: "latest-tag-pod-denies",
			pod: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "p", "namespace": "default"},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "c",
							"image": "nginx:latest",
							"securityContext": map[string]any{
								"runAsNonRoot":             true,
								"allowPrivilegeEscalation": false,
							},
						},
					},
				},
			},
			wantAllowed: false,
			wantRuleIDs: []string{"no-latest-image-tag"},
		},
		{
			name: "missing-security-context-denies",
			pod: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "p", "namespace": "default"},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "c",
							"image": "nginx:1.25",
							// no securityContext on container
						},
					},
				},
			},
			wantAllowed: false,
			wantRuleIDs: []string{"required-security-context"},
		},
		{
			name: "compliant-pod-allows",
			pod: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "p", "namespace": "default"},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "c",
							"image": "nginx:1.25.3",
							"securityContext": map[string]any{
								"runAsNonRoot":             true,
								"allowPrivilegeEscalation": false,
							},
						},
					},
				},
			},
			wantAllowed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.pod)
			require.NoError(t, err)

			res, err := engine.Evaluate(context.Background(), &EvaluationRequest{
				AdmissionRequest: &admissionv1.AdmissionRequest{
					UID:       types.UID("smoke-" + tc.name),
					Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
					Operation: admissionv1.Create,
					Object:    runtime.RawExtension{Raw: raw},
				},
				Operation: "validate",
			})
			require.NoError(t, err)

			assert.Equal(t, tc.wantAllowed, res.Allowed,
				"verdict mismatch; violations=%+v", res.Violations)

			if !tc.wantAllowed {
				firedRules := map[string]bool{}
				for _, v := range res.Violations {
					firedRules[v.RuleID] = true
					// Each violation must carry a non-empty path so the UI
					// can highlight the offending field.
					assert.NotEmpty(t, v.Path, "violation %s has empty path", v.RuleID)
					assert.NotEmpty(t, v.Message, "violation %s has empty message", v.RuleID)
				}
				for _, want := range tc.wantRuleIDs {
					assert.True(t, firedRules[want],
						"expected rule %q to fire; got rules %v", want, firedRules)
				}
			} else {
				assert.Empty(t, res.Violations,
					"compliant pod should produce zero violations, got %+v", res.Violations)
			}
		})
	}
}
