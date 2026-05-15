<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# grafana

## Purpose
Grafana dashboards visualizing kube-policies metrics. Three dashboards cover system overview, security/violation trends, and performance/latency.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `dashboards/` | JSON dashboard definitions importable into Grafana (see `dashboards/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Dashboards reference Prometheus metric names from `internal/metrics/collector.go`. When renaming or removing a metric, update affected dashboards in the same change.
- Variables (datasource, namespace) are templated in each JSON; preserve them when editing or re-exporting from Grafana.

## Dependencies

### External
- Grafana 9+

<!-- MANUAL: -->
