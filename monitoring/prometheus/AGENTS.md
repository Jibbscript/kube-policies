<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# prometheus

## Purpose
Prometheus server configuration: global settings, scrape jobs targeting the admission webhook and policy manager metrics endpoints, and recording/alerting rules.

## Key Files

| File | Description |
|------|-------------|
| `prometheus.yaml` | Global config, scrape configs, and rule file references |

## For AI Agents

### Working In This Directory
- Scrape targets are `:9090` (admission-webhook metrics) and `:9091` (policy-manager metrics). Keep ports consistent with `cmd/admission-webhook/main.go` and `cmd/policy-manager/main.go` defaults.
- Alert rule names must match the routing tree in `monitoring/alertmanager/alertmanager.yaml`.
- Validate config locally with `promtool check config prometheus.yaml` and `promtool check rules <rule-files>` when applicable.

## Dependencies

### External
- Prometheus 2.x

<!-- MANUAL: -->
