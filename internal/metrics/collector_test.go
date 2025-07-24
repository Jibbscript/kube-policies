package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var testCollector *Collector

func init() {
	// Create a single collector instance for all tests to avoid duplicate registration
	testCollector = NewCollector()
}

func TestNewCollector(t *testing.T) {
	assert.NotNil(t, testCollector)
}

func TestMetricsCollector_IncAdmissionRequests(t *testing.T) {
	// Test that methods can be called without panicking
	testCollector.IncAdmissionRequests("validate", "allowed", "PolicyCompliant")
	testCollector.IncAdmissionRequests("validate", "denied", "PolicyViolation")
	testCollector.IncAdmissionRequests("mutate", "allowed", "PolicyCompliant")
}

func TestMetricsCollector_ObserveEvaluationDuration(t *testing.T) {
	// Using shared testCollector

	// Test that duration observation works
	testCollector.ObserveEvaluationDuration("validate", 50*time.Millisecond)
	testCollector.ObserveEvaluationDuration("mutate", 25*time.Millisecond)
}

func TestMetricsCollector_IncPolicyEvaluations(t *testing.T) {
	// Using shared testCollector

	// Test policy evaluation metrics
	testCollector.IncPolicyEvaluations("policy-1", "rule-1", "allowed")
	testCollector.IncPolicyEvaluations("policy-1", "rule-2", "denied")
}

func TestMetricsCollector_IncComplianceViolations(t *testing.T) {
	// Using shared testCollector

	// Test compliance violations
	testCollector.IncComplianceViolations("security-baseline", "HIGH", "security")
	testCollector.IncComplianceViolations("resource-limits", "MEDIUM", "resources")
}

func TestMetricsCollector_SetPoliciesLoaded(t *testing.T) {
	// Using shared testCollector

	// Test setting policies loaded count
	testCollector.SetPoliciesLoaded(5)
	testCollector.SetPoliciesLoaded(10)
}

func TestMetricsCollector_IncSystemErrors(t *testing.T) {
	// Using shared testCollector

	// Test system error metrics
	testCollector.IncSystemErrors("admission", "timeout")
	testCollector.IncSystemErrors("policy", "parse_error")
}

func TestMetricsCollector_IncCacheHits(t *testing.T) {
	// Using shared testCollector

	// Test cache hit metrics
	testCollector.IncCacheHits("policy", "hit")
	testCollector.IncCacheHits("policy", "miss")
}

func TestMetricsCollector_IncAuditEvents(t *testing.T) {
	// Using shared testCollector

	// Test audit event metrics
	testCollector.IncAuditEvents("decision", "success")
	testCollector.IncAuditEvents("config", "error")
}

func TestMetricsCollector_SetAuditBufferSize(t *testing.T) {
	// Using shared testCollector

	// Test audit buffer size
	testCollector.SetAuditBufferSize(100)
	testCollector.SetAuditBufferSize(200)
}

func TestMetricsCollector_IncComplianceReports(t *testing.T) {
	// Using shared testCollector

	// Test compliance report metrics
	testCollector.IncComplianceReports("cis", "success")
	testCollector.IncComplianceReports("nist", "error")
}

func TestMetricsCollector_GetMetrics(t *testing.T) {
	// Using shared testCollector

	// Test that GetMetrics returns a map
	metrics := testCollector.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Greater(t, len(metrics), 0)

	// Check that expected metrics are present
	expectedMetrics := []string{
		"admission_requests",
		"evaluation_duration",
		"policy_evaluations",
		"policies_loaded",
		"compliance_violations",
	}

	for _, metricName := range expectedMetrics {
		assert.Contains(t, metrics, metricName)
	}
}
