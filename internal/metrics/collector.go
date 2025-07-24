package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Collector collects and exposes metrics
type Collector struct {
	// Admission webhook metrics
	admissionRequests  *prometheus.CounterVec
	evaluationDuration *prometheus.HistogramVec
	policyEvaluations  *prometheus.CounterVec

	// Policy management metrics
	policiesLoaded prometheus.Gauge
	policyUpdates  *prometheus.CounterVec

	// System metrics
	systemErrors *prometheus.CounterVec
	cacheHits    *prometheus.CounterVec

	// Audit metrics
	auditEvents     *prometheus.CounterVec
	auditBufferSize prometheus.Gauge

	// Compliance metrics
	complianceViolations *prometheus.CounterVec
	complianceReports    *prometheus.CounterVec
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		admissionRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_policies",
				Subsystem: "admission",
				Name:      "requests_total",
				Help:      "Total number of admission requests processed",
			},
			[]string{"operation", "status", "reason"},
		),

		evaluationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "kube_policies",
				Subsystem: "admission",
				Name:      "evaluation_duration_seconds",
				Help:      "Time spent evaluating policies",
				Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
			},
			[]string{"operation"},
		),

		policyEvaluations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_policies",
				Subsystem: "policy",
				Name:      "evaluations_total",
				Help:      "Total number of policy evaluations",
			},
			[]string{"policy_id", "rule_id", "result"},
		),

		policiesLoaded: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "kube_policies",
				Subsystem: "policy",
				Name:      "loaded_total",
				Help:      "Number of policies currently loaded",
			},
		),

		policyUpdates: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_policies",
				Subsystem: "policy",
				Name:      "updates_total",
				Help:      "Total number of policy updates",
			},
			[]string{"operation", "status"},
		),

		systemErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_policies",
				Subsystem: "system",
				Name:      "errors_total",
				Help:      "Total number of system errors",
			},
			[]string{"component", "error_type"},
		),

		cacheHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_policies",
				Subsystem: "cache",
				Name:      "hits_total",
				Help:      "Total number of cache hits and misses",
			},
			[]string{"cache_type", "result"},
		),

		auditEvents: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_policies",
				Subsystem: "audit",
				Name:      "events_total",
				Help:      "Total number of audit events",
			},
			[]string{"event_type", "status"},
		),

		auditBufferSize: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "kube_policies",
				Subsystem: "audit",
				Name:      "buffer_size",
				Help:      "Current size of the audit event buffer",
			},
		),

		complianceViolations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_policies",
				Subsystem: "compliance",
				Name:      "violations_total",
				Help:      "Total number of compliance violations",
			},
			[]string{"framework", "severity", "category"},
		),

		complianceReports: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "kube_policies",
				Subsystem: "compliance",
				Name:      "reports_total",
				Help:      "Total number of compliance reports generated",
			},
			[]string{"framework", "status"},
		),
	}
}

// IncAdmissionRequests increments the admission requests counter
func (c *Collector) IncAdmissionRequests(operation, status, reason string) {
	c.admissionRequests.WithLabelValues(operation, status, reason).Inc()
}

// ObserveEvaluationDuration observes policy evaluation duration
func (c *Collector) ObserveEvaluationDuration(operation string, duration time.Duration) {
	c.evaluationDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// IncPolicyEvaluations increments the policy evaluations counter
func (c *Collector) IncPolicyEvaluations(policyID, ruleID, result string) {
	c.policyEvaluations.WithLabelValues(policyID, ruleID, result).Inc()
}

// SetPoliciesLoaded sets the number of loaded policies
func (c *Collector) SetPoliciesLoaded(count float64) {
	c.policiesLoaded.Set(count)
}

// IncPolicyUpdates increments the policy updates counter
func (c *Collector) IncPolicyUpdates(operation, status string) {
	c.policyUpdates.WithLabelValues(operation, status).Inc()
}

// IncSystemErrors increments the system errors counter
func (c *Collector) IncSystemErrors(component, errorType string) {
	c.systemErrors.WithLabelValues(component, errorType).Inc()
}

// IncCacheHits increments the cache hits counter
func (c *Collector) IncCacheHits(cacheType, result string) {
	c.cacheHits.WithLabelValues(cacheType, result).Inc()
}

// IncAuditEvents increments the audit events counter
func (c *Collector) IncAuditEvents(eventType, status string) {
	c.auditEvents.WithLabelValues(eventType, status).Inc()
}

// SetAuditBufferSize sets the audit buffer size
func (c *Collector) SetAuditBufferSize(size float64) {
	c.auditBufferSize.Set(size)
}

// IncComplianceViolations increments the compliance violations counter
func (c *Collector) IncComplianceViolations(framework, severity, category string) {
	c.complianceViolations.WithLabelValues(framework, severity, category).Inc()
}

// IncComplianceReports increments the compliance reports counter
func (c *Collector) IncComplianceReports(framework, status string) {
	c.complianceReports.WithLabelValues(framework, status).Inc()
}

// GetMetrics returns all metrics for testing or inspection
func (c *Collector) GetMetrics() map[string]prometheus.Collector {
	return map[string]prometheus.Collector{
		"admission_requests":    c.admissionRequests,
		"evaluation_duration":   c.evaluationDuration,
		"policy_evaluations":    c.policyEvaluations,
		"policies_loaded":       c.policiesLoaded,
		"policy_updates":        c.policyUpdates,
		"system_errors":         c.systemErrors,
		"cache_hits":            c.cacheHits,
		"audit_events":          c.auditEvents,
		"audit_buffer_size":     c.auditBufferSize,
		"compliance_violations": c.complianceViolations,
		"compliance_reports":    c.complianceReports,
	}
}
