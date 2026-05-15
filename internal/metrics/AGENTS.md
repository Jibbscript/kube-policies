<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# metrics

## Purpose
Prometheus collector exposing all kube-policies metrics under namespace `kube_policies`. Covers admission requests, policy evaluation duration, per-rule evaluations, loaded policy count, system errors, cache hits, audit events, and compliance violations/reports.

## Key Files

| File | Description |
|------|-------------|
| `collector.go` | `Collector` struct, `NewCollector`, and per-metric increment/observe helpers |
| `collector_test.go` | Unit tests for the collector |

## For AI Agents

### Working In This Directory
- All counters/histograms register at construction via `promauto.NewCounterVec`/`NewHistogramVec` against the global Prometheus registry. Adding a metric means: declare the field, register it in `NewCollector`, expose a typed setter/inc/observe method, and add it to `GetMetrics()`.
- Subsystems in use: `admission`, `policy`, `audit`, `compliance`, `system`, `cache`. Reuse these before inventing new ones.
- Histogram buckets for `evaluation_duration_seconds` use `ExponentialBuckets(0.001, 2, 10)` (~1ms to ~1s). Resist changing these — dashboards in `monitoring/grafana/dashboards/` and SLO alerts depend on them.
- Label cardinality matters: `policy_id` and `rule_id` labels can grow unbounded if policies are dynamic — keep this in mind before adding new high-cardinality labels.

### Testing Requirements
- Unit tests in `collector_test.go`. Run via `go test ./internal/metrics/...` or `make test-unit`.

## Dependencies

### External
- `github.com/prometheus/client_golang/prometheus`
- `github.com/prometheus/client_golang/prometheus/promauto`

<!-- MANUAL: -->
