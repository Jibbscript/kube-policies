<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# templates

## Purpose
Helm-templated Kubernetes manifests rendered into the target cluster on `helm install/upgrade`. Defines the admission webhook deployment, the policy manager deployment, RBAC bindings, services, and shared template helpers.

## Key Files

| File | Description |
|------|-------------|
| `_helpers.tpl` | Reusable template definitions: name, fullname, labels, selector labels, image references |
| `admission-webhook-deployment.yaml` | Deployment + ValidatingWebhookConfiguration + MutatingWebhookConfiguration for the admission service |
| `policy-manager-deployment.yaml` | Deployment for the policy-manager API service |
| `services.yaml` | ClusterIP Services exposing both pods |
| `rbac.yaml` | ServiceAccount, ClusterRole, and ClusterRoleBinding manifests |

## For AI Agents

### Working In This Directory
- All resources should consume the labels and naming helpers in `_helpers.tpl` so the chart stays consistent under custom release names.
- Every resource referencing an image must use `{{ include "kube-policies.admissionWebhookImage" . }}` (or equivalent) — never hardcode a tag.
- TLS certificates for the webhook are provisioned outside the chart (cert-manager or manual). Templates reference Secret names from `values.yaml`; do not embed certificate material.
- Webhook `failurePolicy` defaults to `Fail` for validate to mirror the runtime `fail-closed` default in `internal/config`. Mutate webhooks should default to `Ignore` to avoid blocking on transient mutation errors.

### Testing Requirements
- `make helm-template` renders the chart with default values — diff this output against expectations during PRs that touch templates.
- `helm lint charts/kube-policies` enforces structural correctness.

## Dependencies

### External
- Helm 3.8+
- Kubernetes 1.20+ (admission webhook configuration v1)

<!-- MANUAL: -->
