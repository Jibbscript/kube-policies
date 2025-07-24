package audit

import (
	"testing"
	"time"

	"github.com/enterprise/kube-policies/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewLogger(t *testing.T) {
	// Test with disabled audit
	auditConfig := &config.AuditConfig{
		Enabled: false,
	}

	logger, err := NewLogger(auditConfig)
	require.NoError(t, err)
	assert.NotNil(t, logger)

	// Test with enabled audit using stdout backend
	auditConfig = &config.AuditConfig{
		Enabled:       true,
		Backend:       "stdout",
		BufferSize:    100,
		FlushInterval: "1s",
	}

	logger, err = NewLogger(auditConfig)
	require.NoError(t, err)
	assert.NotNil(t, logger)

	// Clean up
	err = logger.Close()
	assert.NoError(t, err)
}

func TestLogger_LogDecision(t *testing.T) {
	auditConfig := &config.AuditConfig{
		Enabled:       true,
		Backend:       "stdout",
		BufferSize:    100,
		FlushInterval: "1s",
	}

	logger, err := NewLogger(auditConfig)
	require.NoError(t, err)
	defer logger.Close()

	// Create audit context
	ctx := &Context{
		RequestID: "test-request-123",
		UserInfo: authenticationv1.UserInfo{
			Username: "test-user",
			Groups:   []string{"system:authenticated"},
		},
		Namespace: "default",
		Kind: metav1.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "Pod",
		},
		Name:           "test-pod",
		Operation:      "CREATE",
		Decision:       "ALLOW",
		Reason:         "PolicyCompliant",
		Message:        "All policies passed",
		ProcessingTime: 50 * time.Millisecond,
		Timestamp:      time.Now(),
		Metadata: map[string]interface{}{
			"test": "value",
		},
	}

	// Test that LogDecision doesn't panic
	logger.LogDecision(ctx)
}

func TestLogger_LogConfigChange(t *testing.T) {
	auditConfig := &config.AuditConfig{
		Enabled:       true,
		Backend:       "stdout",
		BufferSize:    100,
		FlushInterval: "1s",
	}

	logger, err := NewLogger(auditConfig)
	require.NoError(t, err)
	defer logger.Close()

	userInfo := authenticationv1.UserInfo{
		Username: "admin",
		Groups:   []string{"system:masters"},
	}

	changes := map[string]interface{}{
		"enabled": true,
		"policy":  "new-policy",
	}

	// Test that LogConfigChange doesn't panic
	logger.LogConfigChange(userInfo, "CREATE", "policy", "test-policy", changes)
}

func TestLogger_LogSystemEvent(t *testing.T) {
	auditConfig := &config.AuditConfig{
		Enabled:       true,
		Backend:       "stdout",
		BufferSize:    100,
		FlushInterval: "1s",
	}

	logger, err := NewLogger(auditConfig)
	require.NoError(t, err)
	defer logger.Close()

	metadata := map[string]interface{}{
		"component": "policy-engine",
		"version":   "1.0.0",
	}

	// Test that LogSystemEvent doesn't panic
	logger.LogSystemEvent("SystemStartup", "Policy engine started", metadata)
}

func TestBackends_Structure(t *testing.T) {
	// Test StdoutBackend
	stdoutBackend := NewStdoutBackend()
	assert.NotNil(t, stdoutBackend)

	// Test that Close doesn't panic
	err := stdoutBackend.Close()
	assert.NoError(t, err)
}
