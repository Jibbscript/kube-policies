<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# alertmanager

## Purpose
Alertmanager configuration controlling how Prometheus alerts from kube-policies are routed and delivered.

## Key Files

| File | Description |
|------|-------------|
| `alertmanager.yaml` | Routing tree, receivers, inhibition rules, and templates |

## For AI Agents

### Working In This Directory
- Alert names referenced here must match those defined in Prometheus rules under `monitoring/prometheus/`.
- Receivers commonly include Slack, PagerDuty, or email; secrets (webhook URLs, tokens) belong in Kubernetes Secrets, never inline in this file.
- Validate locally with `amtool check-config alertmanager.yaml` before deploying.

## Dependencies

### External
- Alertmanager v0.25+

<!-- MANUAL: -->
