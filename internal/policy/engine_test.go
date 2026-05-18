package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/Jibbscript/kube-policies/internal/config"
)

func TestNewEngine(t *testing.T) {
	config := &config.PolicyConfig{
		FailureMode: "fail-closed",
	}
	logger := zap.NewNop()

	engine, err := NewEngine(config, logger)
	require.NoError(t, err)
	assert.NotNil(t, engine)
}

func TestEngineDisableDefaults(t *testing.T) {
	cfg := &config.PolicyConfig{
		FailureMode:     "fail-closed",
		DisableDefaults: true,
	}
	logger := zap.NewNop()

	engine, err := NewEngine(cfg, logger)
	require.NoError(t, err)

	t.Run("no policies loaded", func(t *testing.T) {
		assert.Len(t, engine.ListPolicies(), 0)
		assert.Len(t, engine.policies, 0)
	})

	t.Run("privileged pod is allowed when no policies loaded", func(t *testing.T) {
		privilegedPod := []byte(`{"spec":{"containers":[{"name":"c","image":"nginx:1.0","securityContext":{"privileged":true}}]}}`)
		ar := &admissionv1.AdmissionRequest{}
		ar.Object.Raw = privilegedPod
		req := &EvaluationRequest{
			AdmissionRequest: ar,
			Operation:        "CREATE",
		}
		result, err := engine.Evaluate(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})
}

func TestEngineRejectsMalformedAdmissionObjectJSON(t *testing.T) {
	engine, err := NewEngine(&config.PolicyConfig{
		FailureMode:     "fail-closed",
		DisableDefaults: true,
	}, zap.NewNop())
	require.NoError(t, err)

	_, err = engine.Evaluate(context.Background(), &EvaluationRequest{
		AdmissionRequest: &admissionv1.AdmissionRequest{
			Object: runtimeRaw(`{"apiVersion":"v1","kind":"Pod"`),
		},
		Operation: "CREATE",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid admission object JSON")
}

func TestEngineRejectsNilAdmissionRequest(t *testing.T) {
	engine, err := NewEngine(&config.PolicyConfig{
		FailureMode:     "fail-closed",
		DisableDefaults: true,
	}, zap.NewNop())
	require.NoError(t, err)

	_, err = engine.Evaluate(context.Background(), &EvaluationRequest{
		Operation: "CREATE",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admission request is required")
}

func TestEngineRejectsMalformedOldAdmissionObjectJSON(t *testing.T) {
	engine, err := NewEngine(&config.PolicyConfig{
		FailureMode:     "fail-closed",
		DisableDefaults: true,
	}, zap.NewNop())
	require.NoError(t, err)

	_, err = engine.Evaluate(context.Background(), &EvaluationRequest{
		AdmissionRequest: &admissionv1.AdmissionRequest{
			Object:    runtimeRaw(`{"apiVersion":"v1","kind":"Pod"}`),
			OldObject: runtimeRaw(`{"apiVersion":"v1","kind":"Pod"`),
		},
		Operation: "UPDATE",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid admission oldObject JSON")
}

func TestEngineRejectsMalformedRegoResultContract(t *testing.T) {
	tests := []struct {
		name        string
		regoBody    string
		wantMessage string
	}{
		{
			name: "missing evaluate result",
			regoBody: `package kube_policies

import rego.v1

evaluate := {"allowed": true} if { false }
`,
			wantMessage: "must define data.kube_policies.evaluate",
		},
		{
			name: "non-object result",
			regoBody: `package kube_policies

evaluate := "allow"
`,
			wantMessage: "must be an object",
		},
		{
			name: "missing allowed field",
			regoBody: `package kube_policies

evaluate := {"message": "no decision"}
`,
			wantMessage: "boolean allowed field",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := NewEvaluatorForPolicy(&Policy{
				ID:      "contract",
				Name:    "contract",
				Enabled: true,
				Rules: []Rule{{
					ID:   "contract-rule",
					Name: "contract rule",
					Rego: tc.regoBody,
				}},
			}, &config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
			require.NoError(t, err)

			_, err = engine.Evaluate(context.Background(), &EvaluationRequest{
				AdmissionRequest: &admissionv1.AdmissionRequest{
					Object: runtimeRaw(`{"apiVersion":"v1","kind":"Pod"}`),
				},
				Operation: "CREATE",
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMessage)
		})
	}
}

func TestPolicy_Structure(t *testing.T) {
	// Test that Policy struct can be created
	policy := &Policy{
		ID:          "test-policy",
		Name:        "Test Policy",
		Description: "A test policy",
		Version:     "1.0",
		Enabled:     true,
		Rules: []Rule{
			{
				ID:          "rule-1",
				Name:        "Test Rule",
				Description: "A test rule",
				Rego:        "package test\nallow = true",
				Severity:    "HIGH",
				Category:    "security",
			},
		},
	}

	assert.Equal(t, "test-policy", policy.ID)
	assert.Equal(t, "Test Policy", policy.Name)
	assert.Equal(t, "A test policy", policy.Description)
	assert.Equal(t, "1.0", policy.Version)
	assert.True(t, policy.Enabled)
	assert.Len(t, policy.Rules, 1)
	assert.Equal(t, "rule-1", policy.Rules[0].ID)
}

func runtimeRaw(raw string) runtime.RawExtension {
	return runtime.RawExtension{Raw: []byte(raw)}
}
