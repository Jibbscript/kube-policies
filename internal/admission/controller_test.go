package admission

import (
	"testing"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewController(t *testing.T) {
	// Create dependencies
	policyConfig := &config.PolicyConfig{
		FailureMode: "fail-closed",
		CacheSize:   100,
		Timeout:     "5s",
	}
	logger := zap.NewNop()

	policyEngine, err := policy.NewEngine(policyConfig, logger)
	require.NoError(t, err)

	auditConfig := &config.AuditConfig{
		Enabled: false, // Disable for testing
	}
	auditLogger, err := audit.NewLogger(auditConfig)
	require.NoError(t, err)

	metricsCollector := metrics.NewCollector()

	// Create controller
	controller := NewController(policyEngine, auditLogger, metricsCollector, logger)

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
