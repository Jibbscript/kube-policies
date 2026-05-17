package metrics

import (
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// collectCounterValue returns the float value of a single CounterVec child
// series and the sorted list of label names on the rendered Metric. It uses
// the dto.Metric proto so we don't depend on `prometheus/testutil` (which
// pulls `kylelemons/godebug` as a transitive dep, requiring a `go mod tidy`
// outside this PR's lane).
func collectCounterValue(t *testing.T, c prometheus.Collector) (float64, []string) {
	t.Helper()
	ch := make(chan prometheus.Metric, 1)
	c.Collect(ch)
	close(ch)

	m, ok := <-ch
	require.True(t, ok, "expected one Metric sample from the collector")

	var dtm dto.Metric
	require.NoError(t, m.Write(&dtm))
	require.NotNil(t, dtm.Counter, "expected a Counter sample")

	names := make([]string, 0, len(dtm.Label))
	for _, lp := range dtm.Label {
		names = append(names, lp.GetName())
	}
	sort.Strings(names)
	return dtm.Counter.GetValue(), names
}

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

// TestCollector_IncExceptionSuppression_Increments asserts that the
// `kube_policies_policy_exception_suppressions_total` counter is incremented
// exactly once per IncExceptionSuppression call with the matching label values.
// Closes the C6 acceptance criterion gap surfaced in team-verify (FIX-1).
func TestCollector_IncExceptionSuppression_Increments(t *testing.T) {
	// Use label values unique to this test so the shared testCollector counter
	// child starts at zero regardless of test ordering with the label-set test below.
	const policyID = "policy-fix1-inc"
	const ruleID = "rule-fix1-inc"

	testCollector.IncExceptionSuppression(policyID, ruleID)

	vec, ok := testCollector.GetMetrics()["exception_suppressions"].(*prometheus.CounterVec)
	require.True(t, ok, "exception_suppressions must be a *prometheus.CounterVec")

	val, _ := collectCounterValue(t, vec.WithLabelValues(policyID, ruleID))
	assert.InDelta(t, 1.0, val, 1e-9)

	// Idempotency / second-increment sanity check.
	testCollector.IncExceptionSuppression(policyID, ruleID)
	val, _ = collectCounterValue(t, vec.WithLabelValues(policyID, ruleID))
	assert.InDelta(t, 2.0, val, 1e-9)
}

// TestCollector_ExceptionSuppression_LabelSetIsBounded confirms the metric's
// label set is exactly `{policy_id, rule_id}` — no exception_id, no other
// high-cardinality labels. Anchors the OQ-4 / plan §5.9.a cardinality
// decision: a future change that adds (e.g.) `exception_id` to labels would
// fail this test loudly. Per-exception attribution belongs in the structured
// audit log, not the metric.
func TestCollector_ExceptionSuppression_LabelSetIsBounded(t *testing.T) {
	const policyID = "policy-fix1-bounds"
	const ruleID = "rule-fix1-bounds"

	testCollector.IncExceptionSuppression(policyID, ruleID)

	vec, ok := testCollector.GetMetrics()["exception_suppressions"].(*prometheus.CounterVec)
	require.True(t, ok)

	_, names := collectCounterValue(t, vec.WithLabelValues(policyID, ruleID))
	assert.Equal(t, []string{"policy_id", "rule_id"}, names,
		"label set must be EXACTLY {policy_id, rule_id} — no exception_id, no other high-cardinality labels (plan §5.9.a / OQ-4)")
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
