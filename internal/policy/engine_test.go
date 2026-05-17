package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"

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
