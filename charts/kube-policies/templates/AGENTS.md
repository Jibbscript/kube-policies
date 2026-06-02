<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-15 | Updated: 2026-05-15 -->

# templates

## Purpose
Helm-templated Kubernetes manifests rendered into the target cluster on `helm install/upgrade`. Defines the admission webhook deployment, the policy manager deployment, RBAC bindings, services, and shared template helpers.

## Key Files

| File | Description |
|------|-------------|
| `_helpers.tpl` | Reusable template definitions: name, fullname, labels, selector labels, image references, default pod anti-affinity / topology spread (RES-WU-04), webhook namespaceSelector (RES-WU-09), priorityClass name (RES-WU-20) |
| `admission-webhook-deployment.yaml` | Deployment for the admission service (probes, startupProbe, anti-affinity, terminationGrace/preStop, priorityClassName) |
| `admission-webhook-tls.yaml` | Serving-cert Secret + Validating/Mutating WebhookConfigurations (RES-WU-09; rules + namespaceSelector are values-driven, single source of truth) |
| `admission-webhook-pdb.yaml` / `policy-manager-pdb.yaml` / `dashboard-pdb.yaml` | PodDisruptionBudgets (RES-WU-01/02) |
| `admission-webhook-hpa.yaml` | HorizontalPodAutoscaler for the webhook (RES-WU-18) |
| `priorityclass.yaml` | Cluster-scoped PriorityClass for the control plane (RES-WU-20) |
| `backup-cronjob.yaml` / `backup-rbac.yaml` | Scheduled CRD backup CronJob + least-privilege RBAC (RES-WU-13) |
| `policy-manager-deployment.yaml` | Deployment for the policy-manager API service |
| `services.yaml` | ClusterIP Services exposing both pods |
| `rbac.yaml` | ServiceAccount, ClusterRole, and ClusterRoleBinding manifests |

## For AI Agents

### Working In This Directory
- All resources should consume the labels and naming helpers in `_helpers.tpl` so the chart stays consistent under custom release names.
- Every resource referencing an image must use `{{ include "kube-policies.admissionWebhookImage" . }}` (or equivalent) — never hardcode a tag.
- TLS certificates for the webhook are provisioned outside the chart (cert-manager or manual). Templates reference Secret names from `values.yaml`; do not embed certificate material.
- Webhook `failurePolicy` defaults to `Fail` for validate to mirror the runtime `fail-closed` default in `internal/config`. Mutate webhooks should default to `Ignore` to avoid blocking on transient mutation errors.
- RES-WU-09: the Validating/Mutating webhook `rules` and `namespaceSelector` are values-driven (`admissionWebhook.webhook.rules`, `.mutating.rules`, `.excludedNamespaces`) and the chart is the SINGLE SOURCE OF TRUTH — keep `deployments/kubernetes/base/admission-webhook.yaml` aligned when you change them. The default rule set is **Pods only**, matching the kinds the bundled default policies evaluate. Every kind added under `failurePolicy: Fail` puts the webhook on that kind's write path and widens the fail-closed blast radius, so extend `rules` only when a CRD Policy targets that kind.
- RES-WU-07: graceful drain is image/version-independent via the binary `--shutdown-drain-delay` flag (the runtime images are distroless — no shell for an `exec` preStop, and the native lifecycle `sleep` action is k8s ≥ 1.29). `preStopDrainSeconds` drives both the flag and the (best-effort) native preStop.

### Testing Requirements
- `make helm-template` renders the chart with default values — diff this output against expectations during PRs that touch templates.
- `helm lint charts/kube-policies` enforces structural correctness.

## Dependencies

### External
- Helm 3.8+
- Kubernetes 1.20+ (admission webhook configuration v1)

<!-- MANUAL: -->
