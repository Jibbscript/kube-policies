<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# dashboards

## Purpose
JSON dashboard definitions for Grafana. Provides three perspectives on the kube-policies metrics surface: system overview, security/violations, and performance/latency.

## Key Files

| File | Description |
|------|-------------|
| `kube-policies-overview.json` | High-level service health: request rate, success rate, loaded policies, audit throughput |
| `kube-policies-security.json` | Policy violations by severity/framework, denial rate, exception activity |
| `kube-policies-performance.json` | Evaluation latency percentiles, throughput, cache hit ratio, resource utilization |

## For AI Agents

### Working In This Directory
- Panel queries reference Prometheus metric names from `internal/metrics/collector.go`. When metric names or labels change, update panels here in the same change.
- Dashboard UIDs and titles are stable identifiers — do not regenerate them on cosmetic edits, since users may have bookmarked or alerted on specific UIDs.
- Templating variables (`$datasource`, `$namespace`) must be preserved when re-exporting from Grafana; they are required for the dashboards to be reusable across environments.

## Dependencies

### External
- Grafana 9+
- Prometheus datasource registered in Grafana

<!-- MANUAL: -->
