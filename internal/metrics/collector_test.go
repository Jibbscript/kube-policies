package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsCollector_RecordAdmissionRequest(t *testing.T) {
	collector := NewMetricsCollector()

	// Record some admission requests
	collector.RecordAdmissionRequest("Pod", "default", "ALLOW", 50*time.Millisecond)
	collector.RecordAdmissionRequest("Pod", "default", "DENY", 75*time.Millisecond)
	collector.RecordAdmissionRequest("Deployment", "kube-system", "ALLOW", 25*time.Millisecond)

	// Test admission requests total counter
	expected := `
		# HELP kube_policies_admission_requests_total Total number of admission requests processed
		# TYPE kube_policies_admission_requests_total counter
		kube_policies_admission_requests_total{kind="Deployment",namespace="kube-system",result="ALLOW"} 1
		kube_policies_admission_requests_total{kind="Pod",namespace="default",result="ALLOW"} 1
		kube_policies_admission_requests_total{kind="Pod",namespace="default",result="DENY"} 1
	`

	err := testutil.GatherAndCompare(collector.registry, strings.NewReader(expected), "kube_policies_admission_requests_total")
	require.NoError(t, err)

	// Test admission duration histogram
	durationMetric := testutil.ToFloat64(collector.admissionDuration.WithLabelValues("Pod", "default", "ALLOW"))
	assert.Equal(t, float64(1), durationMetric) // One observation for Pod/default/ALLOW

	durationMetric = testutil.ToFloat64(collector.admissionDuration.WithLabelValues("Pod", "default", "DENY"))
	assert.Equal(t, float64(1), durationMetric) // One observation for Pod/default/DENY
}

func TestMetricsCollector_RecordPolicyViolation(t *testing.T) {
	collector := NewMetricsCollector()

	// Record some policy violations
	collector.RecordPolicyViolation("security-baseline", "no-privileged-containers", "HIGH", "Pod", "default")
	collector.RecordPolicyViolation("security-baseline", "no-root-user", "HIGH", "Pod", "default")
	collector.RecordPolicyViolation("resource-limits", "require-limits", "MEDIUM", "Deployment", "production")

	// Test policy violations counter
	expected := `
		# HELP kube_policies_policy_violations_total Total number of policy violations detected
		# TYPE kube_policies_policy_violations_total counter
		kube_policies_policy_violations_total{kind="Deployment",namespace="production",policy="resource-limits",rule="require-limits",severity="MEDIUM"} 1
		kube_policies_policy_violations_total{kind="Pod",namespace="default",policy="security-baseline",rule="no-privileged-containers",severity="HIGH"} 1
		kube_policies_policy_violations_total{kind="Pod",namespace="default",policy="security-baseline",rule="no-root-user",severity="HIGH"} 1
	`

	err := testutil.GatherAndCompare(collector.registry, strings.NewReader(expected), "kube_policies_policy_violations_total")
	require.NoError(t, err)
}

func TestMetricsCollector_RecordPolicyEvaluation(t *testing.T) {
	collector := NewMetricsCollector()

	// Record policy evaluations
	collector.RecordPolicyEvaluation("security-baseline", "SUCCESS", 10*time.Millisecond)
	collector.RecordPolicyEvaluation("security-baseline", "SUCCESS", 15*time.Millisecond)
	collector.RecordPolicyEvaluation("resource-limits", "ERROR", 5*time.Millisecond)

	// Test policy evaluations counter
	expected := `
		# HELP kube_policies_policy_evaluations_total Total number of policy evaluations performed
		# TYPE kube_policies_policy_evaluations_total counter
		kube_policies_policy_evaluations_total{policy="resource-limits",result="ERROR"} 1
		kube_policies_policy_evaluations_total{policy="security-baseline",result="SUCCESS"} 2
	`

	err := testutil.GatherAndCompare(collector.registry, strings.NewReader(expected), "kube_policies_policy_evaluations_total")
	require.NoError(t, err)

	// Test policy evaluation duration
	durationMetric := testutil.ToFloat64(collector.policyEvaluationDuration.WithLabelValues("security-baseline", "SUCCESS"))
	assert.Equal(t, float64(2), durationMetric) // Two observations for security-baseline/SUCCESS
}

func TestMetricsCollector_SetActivePolicies(t *testing.T) {
	collector := NewMetricsCollector()

	// Set active policies
	collector.SetActivePolicies(5)
	collector.SetActivePolicies(7)

	// Test active policies gauge
	expected := `
		# HELP kube_policies_active_policies_total Number of currently active policies
		# TYPE kube_policies_active_policies_total gauge
		kube_policies_active_policies_total 7
	`

	err := testutil.GatherAndCompare(collector.registry, strings.NewReader(expected), "kube_policies_active_policies_total")
	require.NoError(t, err)
}

func TestMetricsCollector_RecordWebhookError(t *testing.T) {
	collector := NewMetricsCollector()

	// Record webhook errors
	collector.RecordWebhookError("admission-webhook", "TIMEOUT")
	collector.RecordWebhookError("admission-webhook", "PARSE_ERROR")
	collector.RecordWebhookError("policy-manager", "CONNECTION_ERROR")

	// Test webhook errors counter
	expected := `
		# HELP kube_policies_webhook_errors_total Total number of webhook errors
		# TYPE kube_policies_webhook_errors_total counter
		kube_policies_webhook_errors_total{component="admission-webhook",error_type="PARSE_ERROR"} 1
		kube_policies_webhook_errors_total{component="admission-webhook",error_type="TIMEOUT"} 1
		kube_policies_webhook_errors_total{component="policy-manager",error_type="CONNECTION_ERROR"} 1
	`

	err := testutil.GatherAndCompare(collector.registry, strings.NewReader(expected), "kube_policies_webhook_errors_total")
	require.NoError(t, err)
}

func TestMetricsCollector_RecordCacheOperation(t *testing.T) {
	collector := NewMetricsCollector()

	// Record cache operations
	collector.RecordCacheOperation("policy", "HIT")
	collector.RecordCacheOperation("policy", "HIT")
	collector.RecordCacheOperation("policy", "MISS")
	collector.RecordCacheOperation("resource", "HIT")

	// Test cache operations counter
	expected := `
		# HELP kube_policies_cache_operations_total Total number of cache operations
		# TYPE kube_policies_cache_operations_total counter
		kube_policies_cache_operations_total{cache_type="policy",result="HIT"} 2
		kube_policies_cache_operations_total{cache_type="policy",result="MISS"} 1
		kube_policies_cache_operations_total{cache_type="resource",result="HIT"} 1
	`

	err := testutil.GatherAndCompare(collector.registry, strings.NewReader(expected), "kube_policies_cache_operations_total")
	require.NoError(t, err)
}

func TestMetricsCollector_RecordAuditEvent(t *testing.T) {
	collector := NewMetricsCollector()

	// Record audit events
	collector.RecordAuditEvent("file", "SUCCESS")
	collector.RecordAuditEvent("file", "SUCCESS")
	collector.RecordAuditEvent("webhook", "ERROR")
	collector.RecordAuditEvent("elasticsearch", "SUCCESS")

	// Test audit events counter
	expected := `
		# HELP kube_policies_audit_events_total Total number of audit events processed
		# TYPE kube_policies_audit_events_total counter
		kube_policies_audit_events_total{backend="elasticsearch",result="SUCCESS"} 1
		kube_policies_audit_events_total{backend="file",result="SUCCESS"} 2
		kube_policies_audit_events_total{backend="webhook",result="ERROR"} 1
	`

	err := testutil.GatherAndCompare(collector.registry, strings.NewReader(expected), "kube_policies_audit_events_total")
	require.NoError(t, err)
}

func TestMetricsCollector_SetResourceCount(t *testing.T) {
	collector := NewMetricsCollector()

	// Set resource counts
	collector.SetResourceCount("Pod", "default", 10)
	collector.SetResourceCount("Pod", "production", 25)
	collector.SetResourceCount("Deployment", "default", 5)

	// Test resource count gauge
	expected := `
		# HELP kube_policies_monitored_resources_total Number of resources currently being monitored
		# TYPE kube_policies_monitored_resources_total gauge
		kube_policies_monitored_resources_total{kind="Deployment",namespace="default"} 5
		kube_policies_monitored_resources_total{kind="Pod",namespace="default"} 10
		kube_policies_monitored_resources_total{kind="Pod",namespace="production"} 25
	`

	err := testutil.GatherAndCompare(collector.registry, strings.NewReader(expected), "kube_policies_monitored_resources_total")
	require.NoError(t, err)
}

func TestMetricsCollector_RecordComplianceScore(t *testing.T) {
	collector := NewMetricsCollector()

	// Record compliance scores
	collector.RecordComplianceScore("CIS", "1.6", 0.95)
	collector.RecordComplianceScore("NIST", "2.0", 0.87)
	collector.RecordComplianceScore("PCI", "3.2", 0.92)

	// Test compliance score gauge
	expected := `
		# HELP kube_policies_compliance_score Compliance score for various frameworks
		# TYPE kube_policies_compliance_score gauge
		kube_policies_compliance_score{framework="CIS",version="1.6"} 0.95
		kube_policies_compliance_score{framework="NIST",version="2.0"} 0.87
		kube_policies_compliance_score{framework="PCI",version="3.2"} 0.92
	`

	err := testutil.GatherAndCompare(collector.registry, strings.NewReader(expected), "kube_policies_compliance_score")
	require.NoError(t, err)
}

func TestMetricsCollector_GetRegistry(t *testing.T) {
	collector := NewMetricsCollector()

	registry := collector.GetRegistry()
	assert.NotNil(t, registry)
	assert.IsType(t, &prometheus.Registry{}, registry)

	// Verify that metrics are registered
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	// Should have all the metrics we defined
	expectedMetrics := []string{
		"kube_policies_admission_requests_total",
		"kube_policies_admission_duration_seconds",
		"kube_policies_policy_violations_total",
		"kube_policies_policy_evaluations_total",
		"kube_policies_policy_evaluation_duration_seconds",
		"kube_policies_active_policies_total",
		"kube_policies_webhook_errors_total",
		"kube_policies_cache_operations_total",
		"kube_policies_audit_events_total",
		"kube_policies_monitored_resources_total",
		"kube_policies_compliance_score",
	}

	metricNames := make([]string, len(metricFamilies))
	for i, mf := range metricFamilies {
		metricNames[i] = mf.GetName()
	}

	for _, expectedMetric := range expectedMetrics {
		assert.Contains(t, metricNames, expectedMetric)
	}
}

func TestMetricsCollector_ConcurrentAccess(t *testing.T) {
	collector := NewMetricsCollector()

	// Test concurrent access to metrics
	done := make(chan bool)
	numGoroutines := 10
	numOperations := 100

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				collector.RecordAdmissionRequest("Pod", "default", "ALLOW", time.Millisecond)
				collector.RecordPolicyViolation("test-policy", "test-rule", "HIGH", "Pod", "default")
				collector.RecordPolicyEvaluation("test-policy", "SUCCESS", time.Millisecond)
				collector.SetActivePolicies(5)
				collector.RecordWebhookError("test-component", "TEST_ERROR")
				collector.RecordCacheOperation("test", "HIT")
				collector.RecordAuditEvent("test", "SUCCESS")
				collector.SetResourceCount("Pod", "default", 10)
				collector.RecordComplianceScore("TEST", "1.0", 0.9)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify that metrics were recorded correctly
	totalRequests := testutil.ToFloat64(collector.admissionRequests.WithLabelValues("Pod", "default", "ALLOW"))
	assert.Equal(t, float64(numGoroutines*numOperations), totalRequests)

	totalViolations := testutil.ToFloat64(collector.policyViolations.WithLabelValues("test-policy", "test-rule", "HIGH", "Pod", "default"))
	assert.Equal(t, float64(numGoroutines*numOperations), totalViolations)
}

// Benchmark tests
func BenchmarkMetricsCollector_RecordAdmissionRequest(b *testing.B) {
	collector := NewMetricsCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordAdmissionRequest("Pod", "default", "ALLOW", time.Millisecond)
	}
}

func BenchmarkMetricsCollector_RecordPolicyViolation(b *testing.B) {
	collector := NewMetricsCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordPolicyViolation("security-baseline", "no-privileged", "HIGH", "Pod", "default")
	}
}

func BenchmarkMetricsCollector_RecordPolicyEvaluation(b *testing.B) {
	collector := NewMetricsCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordPolicyEvaluation("security-baseline", "SUCCESS", time.Millisecond)
	}
}

func BenchmarkMetricsCollector_ConcurrentOperations(b *testing.B) {
	collector := NewMetricsCollector()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			collector.RecordAdmissionRequest("Pod", "default", "ALLOW", time.Millisecond)
			collector.RecordPolicyViolation("test-policy", "test-rule", "HIGH", "Pod", "default")
			collector.RecordPolicyEvaluation("test-policy", "SUCCESS", time.Millisecond)
		}
	})
}

