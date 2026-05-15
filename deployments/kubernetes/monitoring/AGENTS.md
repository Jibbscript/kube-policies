<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# monitoring

## Purpose
Kubernetes Deployments, Services, and ConfigMaps to bring up the observability stack — Prometheus, Grafana, and Alertmanager — already preconfigured for the kube-policies metrics.

## Key Files

| File | Description |
|------|-------------|
| `prometheus-deployment.yaml` | Prometheus Deployment + Service + ConfigMap (consumes `monitoring/prometheus/prometheus.yaml`) |
| `grafana-deployment.yaml` | Grafana Deployment + Service + dashboards provisioning ConfigMap |
| `alertmanager-deployment.yaml` | Alertmanager Deployment + Service + ConfigMap (consumes `monitoring/alertmanager/alertmanager.yaml`) |

## For AI Agents

### Working In This Directory
- ConfigMaps embed content sourced from the standalone files under `monitoring/`. Keep them aligned — these manifests are authoritative for what runs in-cluster.
- Applied via `make deploy-monitoring`. Order: Prometheus → Alertmanager → Grafana so dashboards have a working datasource on first render.
- Resource requests/limits should match the operational profile of the target cluster; defaults here are tuned for development/Kind, not production.

## Dependencies

### External
- `kubectl`
- Prometheus, Grafana, Alertmanager container images

<!-- MANUAL: -->
