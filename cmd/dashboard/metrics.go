package main

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"go.uber.org/zap"
)

// In prometheus/common v0.67+, expfmt.TextParser carries its OWN ValidationScheme
// field (separate from the deprecated package-level model.NameValidationScheme).
// A zero-value TextParser holds UnsetValidation and panics with
// "Invalid name validation scheme requested: unset" on the first metric name.
// Construct via NewTextParser with an explicit scheme.

// MetricsSummary is the JSON contract returned by GET /api/metrics/summary.
//
// The schema is mirrored in web/src/lib/types.ts (T3). Keep the JSON tags
// stable — the SPA depends on these field names.
type MetricsSummary struct {
	AdmissionRPS             float64            `json:"admission_rps"`
	EvalP95Ms                float64            `json:"eval_p95_ms"`
	DenialsPerMin            float64            `json:"denials_per_min"`
	PoliciesLoaded           int                `json:"policies_loaded"`
	AuditBuffer              float64            `json:"audit_buffer"`
	TopViolatingRules        []TopViolatingRule `json:"top_violating_rules"`
	PolicyManagerDegraded    bool               `json:"policy_manager_degraded"`
	AdmissionWebhookDegraded bool               `json:"admission_webhook_degraded"`
}

// TopViolatingRule is one entry in MetricsSummary.TopViolatingRules.
type TopViolatingRule struct {
	RuleID string  `json:"rule_id"`
	Count  float64 `json:"count"`
}

// metricsClient is the HTTP client used to scrape upstream /metrics. Kept
// short-timeout so a hung upstream cannot stall the summary endpoint.
var metricsClient = &http.Client{Timeout: 5 * time.Second}

// NewMetricsHandler returns a handler for GET /api/metrics/summary.
//
// It scrapes both upstream /metrics endpoints in parallel, parses Prometheus
// text exposition format, and returns a typed summary. Failures of either
// upstream are reported via the per-source *Degraded flags but never
// surface as a 5xx — the endpoint always returns 200 (acceptance #8).
func NewMetricsHandler(cfg *Config, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
		defer cancel()

		var (
			pmFamilies, awFamilies map[string]*dto.MetricFamily
			pmErr, awErr           error
			wg                     sync.WaitGroup
		)

		wg.Add(2)
		go func() {
			defer wg.Done()
			pmFamilies, pmErr = scrapeMetrics(ctx, cfg.PolicyManagerMetricsURL)
		}()
		go func() {
			defer wg.Done()
			awFamilies, awErr = scrapeMetrics(ctx, cfg.AdmissionWebhookMetricsURL)
		}()
		wg.Wait()

		summary := MetricsSummary{TopViolatingRules: []TopViolatingRule{}}

		if pmErr != nil {
			summary.PolicyManagerDegraded = true
			log.Warn("policy-manager metrics scrape failed",
				zap.String("url", cfg.PolicyManagerMetricsURL),
				zap.Error(pmErr),
			)
		} else {
			applyPolicyManagerMetrics(&summary, pmFamilies)
		}

		if awErr != nil {
			summary.AdmissionWebhookDegraded = true
			log.Warn("admission-webhook metrics scrape failed",
				zap.String("url", cfg.AdmissionWebhookMetricsURL),
				zap.Error(awErr),
			)
		} else {
			applyAdmissionWebhookMetrics(&summary, awFamilies)
		}

		c.JSON(http.StatusOK, summary)
	}
}

// scrapeMetrics fetches and parses a Prometheus text-format /metrics endpoint.
// Returns an error if the upstream is unreachable, returns non-2xx, or
// produces unparseable output.
func scrapeMetrics(ctx context.Context, url string) (map[string]*dto.MetricFamily, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := metricsClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain to allow connection reuse but cap the read.
		_, _ = io.CopyN(io.Discard, resp.Body, 1<<10)
		return nil, errors.New("non-2xx status from metrics endpoint")
	}
	return parseExposition(resp.Body)
}

// parseExposition runs the standard Prometheus text-format parser. Exposed
// for tests so they can feed canned payloads through the same path.
// UTF8Validation is the modern default (matches client_golang's emission).
func parseExposition(r io.Reader) (map[string]*dto.MetricFamily, error) {
	p := expfmt.NewTextParser(model.UTF8Validation)
	return p.TextToMetricFamilies(r)
}

// applyAdmissionWebhookMetrics maps families from the admission webhook's
// /metrics endpoint onto the summary. Missing metrics yield zero values.
func applyAdmissionWebhookMetrics(s *MetricsSummary, families map[string]*dto.MetricFamily) {
	// admission_rps: total requests (M1: cumulative counter; the SPA observes
	// growth across refreshes). Real per-second rate is M2.
	s.AdmissionRPS += sumCounter(families["kube_policies_admission_requests_total"], nil)

	// denials_per_min: same caveat — sum of denials counter.
	s.DenialsPerMin += sumCounter(
		families["kube_policies_admission_requests_total"],
		map[string]string{"status": "denied"},
	)

	// eval_p95_ms: derive p95 from the evaluation_duration histogram buckets.
	if p95, ok := histogramP95Seconds(families["kube_policies_admission_evaluation_duration_seconds"]); ok {
		s.EvalP95Ms = p95 * 1000.0
	}

	// audit_buffer: gauge.
	s.AuditBuffer += gaugeValue(families["kube_policies_audit_buffer_size"])
}

// applyPolicyManagerMetrics maps families from the policy-manager's /metrics
// endpoint onto the summary. policies_loaded lives here; the engine and
// audit buffer also re-export through the policy-manager process so we
// merge anything we find rather than insist on a strict source split.
func applyPolicyManagerMetrics(s *MetricsSummary, families map[string]*dto.MetricFamily) {
	if v := gaugeValue(families["kube_policies_policy_loaded_total"]); v > 0 {
		s.PoliciesLoaded = int(v)
	}
	// If the policy-manager also reports admission/audit metrics, fold them
	// in so the summary is a union view.
	s.AdmissionRPS += sumCounter(families["kube_policies_admission_requests_total"], nil)
	s.DenialsPerMin += sumCounter(
		families["kube_policies_admission_requests_total"],
		map[string]string{"status": "denied"},
	)
	s.AuditBuffer += gaugeValue(families["kube_policies_audit_buffer_size"])

	// Top-5 violating rules from policy_evaluations_total. We consider any
	// result != "allowed" as a violation contribution.
	s.TopViolatingRules = topViolatingRules(families["kube_policies_policy_evaluations_total"], 5)
}

// sumCounter sums all metrics in a Counter family whose labels match every
// key/value in filter. A nil filter matches all series.
func sumCounter(mf *dto.MetricFamily, filter map[string]string) float64 {
	if mf == nil {
		return 0
	}
	var total float64
	for _, m := range mf.GetMetric() {
		if !labelsMatch(m, filter) {
			continue
		}
		if c := m.GetCounter(); c != nil {
			total += c.GetValue()
		}
	}
	return total
}

// gaugeValue returns the value of the first gauge in a Gauge family. Gauges
// are typically singletons in this codebase; if multiple series exist we
// take the first deterministic one.
func gaugeValue(mf *dto.MetricFamily) float64 {
	if mf == nil {
		return 0
	}
	for _, m := range mf.GetMetric() {
		if g := m.GetGauge(); g != nil {
			return g.GetValue()
		}
	}
	return 0
}

// histogramP95Seconds computes the 95th percentile across all series in a
// Histogram family using linear interpolation within the bucket that crosses
// the 95% cumulative-count threshold. Returns (value, true) on success.
//
// This is an approximation suitable for an operator dashboard, not a precise
// quantile. It walks buckets in ascending UpperBound order, picks the
// crossing bucket, and interpolates between the previous and current
// upper-bound by the cumulative-count delta.
func histogramP95Seconds(mf *dto.MetricFamily) (float64, bool) {
	if mf == nil {
		return 0, false
	}
	var (
		totalCount uint64
		buckets    = map[float64]uint64{}
	)
	for _, m := range mf.GetMetric() {
		h := m.GetHistogram()
		if h == nil {
			continue
		}
		totalCount += h.GetSampleCount()
		for _, b := range h.GetBucket() {
			buckets[b.GetUpperBound()] += b.GetCumulativeCount()
		}
	}
	if totalCount == 0 || len(buckets) == 0 {
		return 0, false
	}
	target := 0.95 * float64(totalCount)

	bounds := make([]float64, 0, len(buckets))
	for ub := range buckets {
		bounds = append(bounds, ub)
	}
	sort.Float64s(bounds)

	var prevBound float64
	var prevCount float64
	for _, ub := range bounds {
		cum := float64(buckets[ub])
		if cum >= target {
			// Quantile falls in the `le="+Inf"` overflow bucket: we don't
			// have a finite upper bound, and linear interpolation would
			// produce +Inf. json.Marshal cannot serialize +Inf and gin
			// silently aborts the response — the client sees HTTP 200 with
			// Content-Length: 0 and no logged panic. Report the highest
			// finite bound observed (prevBound) instead, matching the
			// behavior of Prometheus's histogram_quantile().
			if math.IsInf(ub, 0) || math.IsNaN(ub) {
				return prevBound, true
			}
			if cum == prevCount {
				return ub, true
			}
			frac := (target - prevCount) / (cum - prevCount)
			result := prevBound + frac*(ub-prevBound)
			if math.IsInf(result, 0) || math.IsNaN(result) {
				return prevBound, true
			}
			return result, true
		}
		prevBound = ub
		prevCount = cum
	}
	// Above all buckets; return the highest finite upper bound to avoid
	// emitting +Inf when the largest bound itself is the overflow bucket.
	last := bounds[len(bounds)-1]
	if math.IsInf(last, 0) || math.IsNaN(last) {
		return prevBound, true
	}
	return last, true
}

// topViolatingRules returns the top-N rule_ids by summed counter value where
// the "result" label is anything other than "allowed". Sorted descending by
// count, ties broken by rule_id ascending for determinism.
func topViolatingRules(mf *dto.MetricFamily, n int) []TopViolatingRule {
	out := []TopViolatingRule{}
	if mf == nil || n <= 0 {
		return out
	}
	agg := map[string]float64{}
	for _, m := range mf.GetMetric() {
		var ruleID, result string
		for _, lp := range m.GetLabel() {
			switch lp.GetName() {
			case "rule_id":
				ruleID = lp.GetValue()
			case "result":
				result = lp.GetValue()
			}
		}
		if ruleID == "" {
			continue
		}
		if result == "allowed" || result == "allow" {
			continue
		}
		if c := m.GetCounter(); c != nil {
			agg[ruleID] += c.GetValue()
		}
	}
	for id, count := range agg {
		out = append(out, TopViolatingRule{RuleID: id, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].RuleID < out[j].RuleID
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// labelsMatch reports whether every key/value in filter is present on m.
// A nil filter is treated as "match all".
func labelsMatch(m *dto.Metric, filter map[string]string) bool {
	if len(filter) == 0 {
		return true
	}
	have := map[string]string{}
	for _, lp := range m.GetLabel() {
		have[lp.GetName()] = lp.GetValue()
	}
	for k, v := range filter {
		if have[k] != v {
			return false
		}
	}
	return true
}
