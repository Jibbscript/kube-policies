<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# base

## Purpose
Baseline Kubernetes manifests for the admission webhook. Intended for `kubectl apply -f` workflows where Helm is not available, and as a reference implementation for what the chart renders.

## Key Files

| File | Description |
|------|-------------|
| `admission-webhook.yaml` | Namespace, ServiceAccount, RBAC, Deployment, Service, ValidatingWebhookConfiguration, and MutatingWebhookConfiguration for the admission webhook |

## For AI Agents

### Working In This Directory
- Must stay structurally consistent with `charts/kube-policies/templates/admission-webhook-deployment.yaml`. When updating one, audit the other.
- Image references hardcode tags here. Either tag explicitly (recommended) or use a documented placeholder; do not rely on `:latest`.
- Apply ordering matters: namespace first, then RBAC, then Deployment/Service, then webhook configurations (which reference the Service).

## Dependencies

### External
- `kubectl` against a Kubernetes 1.20+ cluster

<!-- MANUAL: -->
