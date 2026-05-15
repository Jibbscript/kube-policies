<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# monitoring

## Purpose
Standalone configuration for the observability stack: Prometheus scrape config, Grafana dashboards (overview, security, performance), and Alertmanager routing/receivers. These are referenced by the deployment manifests under `deployments/kubernetes/monitoring/`.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `prometheus/` | Prometheus server configuration including scrape targets and rules (see `prometheus/AGENTS.md`) |
| `grafana/` | Grafana dashboard JSON definitions (see `grafana/AGENTS.md`) |
| `alertmanager/` | Alertmanager routing and receiver configuration (see `alertmanager/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Metric names referenced here must match what `internal/metrics/collector.go` registers (namespace `kube_policies`, subsystems `admission`, `policy`, `audit`, `compliance`, `system`, `cache`). When adding a metric in code, update the relevant dashboard or rule.
- Alert thresholds (latency, error rate, violation rate) are the SLO contract for the project — change them deliberately.

### Testing Requirements
- No automated tests in this directory. Validate by deploying to a Kind cluster and viewing dashboards.

## Dependencies

### External
- Prometheus 2.x
- Grafana 9+
- Alertmanager

<!-- MANUAL: -->
