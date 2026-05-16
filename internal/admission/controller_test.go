package admission

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/policy"
)

func TestNewController(t *testing.T) {
	// Create dependencies
	policyConfig := &config.PolicyConfig{
		FailureMode: "fail-closed",
	}
	logger := zap.NewNop()

	policyEngine, err := policy.NewEngine(policyConfig, logger)
	require.NoError(t, err)

	auditConfig := &config.AuditConfig{
		Enabled: false, // Disable for testing
	}
	auditLogger, err := audit.NewLogger(auditConfig)
	require.NoError(t, err)

	// sharedMetrics is defined in controller_behavior_test.go to avoid
	// duplicate Prometheus registration when NewCollector is called twice.
	controller := NewController(policyEngine, auditLogger, sharedMetrics, logger, nil)

	// Verify controller was created
	assert.NotNil(t, controller)
}

func TestController_Structure(t *testing.T) {
	// Test that Controller struct can be created with nil dependencies for structure testing
	controller := &Controller{
		policyEngine: nil,
		auditLogger:  nil,
		metrics:      nil,
		logger:       nil,
	}

	assert.NotNil(t, controller)
}
