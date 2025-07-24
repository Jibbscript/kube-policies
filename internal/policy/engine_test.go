package policy

import (
	"testing"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewEngine(t *testing.T) {
	config := &config.PolicyConfig{
		FailureMode: "fail-closed",
		CacheSize:   100,
		Timeout:     "5s",
	}
	logger := zap.NewNop()

	engine, err := NewEngine(config, logger)
	require.NoError(t, err)
	assert.NotNil(t, engine)
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
	assert.True(t, policy.Enabled)
	assert.Len(t, policy.Rules, 1)
	assert.Equal(t, "rule-1", policy.Rules[0].ID)
}
