{{/*
Expand the name of the chart.
*/}}
{{- define "kube-policies.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kube-policies.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kube-policies.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kube-policies.labels" -}}
helm.sh/chart: {{ include "kube-policies.chart" . }}
{{ include "kube-policies.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kube-policies.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kube-policies.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kube-policies.serviceAccountName" -}}
{{- if .Values.rbac.serviceAccount.create }}
{{- default (include "kube-policies.fullname" .) .Values.rbac.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.rbac.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the admission webhook
*/}}
{{- define "kube-policies.admissionWebhookName" -}}
{{- printf "%s-admission-webhook" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the name of the policy manager
*/}}
{{- define "kube-policies.policyManagerName" -}}
{{- printf "%s-policy-manager" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the webhook service name
*/}}
{{- define "kube-policies.webhookServiceName" -}}
{{- printf "%s-admission-webhook" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the webhook configuration name
*/}}
{{- define "kube-policies.webhookConfigName" -}}
{{- printf "%s-admission-webhook" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the certificate secret name
*/}}
{{- define "kube-policies.certSecretName" -}}
{{- printf "%s-admission-webhook-certs" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the config map name
*/}}
{{- define "kube-policies.configMapName" -}}
{{- printf "%s-config" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the prometheus service monitor name
*/}}
{{- define "kube-policies.serviceMonitorName" -}}
{{- printf "%s-service-monitor" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the prometheus rules name
*/}}
{{- define "kube-policies.prometheusRulesName" -}}
{{- printf "%s-prometheus-rules" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the namespace for monitoring resources
*/}}
{{- define "kube-policies.monitoringNamespace" -}}
{{- .Values.monitoring.serviceMonitor.namespace | default .Release.Namespace }}
{{- end }}

{{/*
Return the appropriate apiVersion for RBAC resources
*/}}
{{- define "kube-policies.rbac.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "rbac.authorization.k8s.io/v1" -}}
rbac.authorization.k8s.io/v1
{{- else -}}
rbac.authorization.k8s.io/v1beta1
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for admission registration
*/}}
{{- define "kube-policies.admissionregistration.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "admissionregistration.k8s.io/v1" -}}
admissionregistration.k8s.io/v1
{{- else -}}
admissionregistration.k8s.io/v1beta1
{{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for policy CRDs
*/}}
{{- define "kube-policies.crd.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "apiextensions.k8s.io/v1" -}}
apiextensions.k8s.io/v1
{{- else -}}
apiextensions.k8s.io/v1beta1
{{- end -}}
{{- end -}}

{{/*
Return the target Kubernetes version
*/}}
{{- define "kube-policies.kubeVersion" -}}
{{- default .Capabilities.KubeVersion.Version .Values.kubeVersionOverride -}}
{{- end -}}

{{/*
Render a full image reference, choosing between:
  - {{ registry }}/{{ repository }}:{{ tag }}     when registry is non-empty AND
                                                  repository's first slash-segment
                                                  does NOT contain a "." or ":" and
                                                  is NOT exactly "localhost".
  - {{ repository }}:{{ tag }}                    when registry is empty OR repository
                                                  looks like a fully-qualified ref.

Detection: a "fully-qualified" repository is one whose first slash-separated segment:
  - contains "." (e.g., docker.io, ghcr.io, quay.io), OR
  - contains ":" (e.g., localhost:5001), OR
  - is exactly "localhost".

This intentionally suppresses a global registry mirror override when the
repository already encodes a registry — applying both would double-prefix.
Operators wanting a mirror should either set image.repository to a host-less
path (e.g., "kube-policies/admission-webhook") and set image.registry to the
mirror host, OR override the full repository (including the host) and leave
image.registry empty.

Inputs: a dict with keys {registry, repository, tag, defaultTag}.
*/}}
{{- define "kube-policies.image" -}}
{{- $registry := .registry | default "" -}}
{{- $repository := required "kube-policies.image: repository is required" .repository -}}
{{- $tag := .tag | default .defaultTag -}}
{{- $first := (split "/" $repository)._0 -}}
{{- $qualified := or (contains "." $first) (or (contains ":" $first) (eq $first "localhost")) -}}
{{- if or (eq $registry "") $qualified -}}
{{ $repository }}:{{ $tag }}
{{- else -}}
{{ $registry }}/{{ $repository }}:{{ $tag }}
{{- end -}}
{{- end -}}

{{/*
Validate required values
*/}}
{{- define "kube-policies.validateValues" -}}
{{- if and .Values.admissionWebhook.enabled (not .Values.admissionWebhook.image.repository) -}}
{{- fail "admissionWebhook.image.repository is required when admissionWebhook is enabled" -}}
{{- end -}}
{{- if and .Values.policyManager.enabled (not .Values.policyManager.image.repository) -}}
{{- fail "policyManager.image.repository is required when policyManager is enabled" -}}
{{- end -}}
{{- if and .Values.admissionWebhook.enabled (ne (.Values.admissionWebhook.image.registry | default "") "") -}}
  {{- $first := (split "/" .Values.admissionWebhook.image.repository)._0 -}}
  {{- if or (contains "." $first) (or (contains ":" $first) (eq $first "localhost")) -}}
    {{- fail (printf "admissionWebhook.image: registry=%q AND repository=%q where repository's first slash-segment %q looks fully-qualified. Set image.registry='' OR set image.repository to a host-less path. See NOTES.txt." .Values.admissionWebhook.image.registry .Values.admissionWebhook.image.repository $first) -}}
  {{- end -}}
{{- end -}}
{{- if and .Values.policyManager.enabled (ne (.Values.policyManager.image.registry | default "") "") -}}
  {{- $first := (split "/" .Values.policyManager.image.repository)._0 -}}
  {{- if or (contains "." $first) (or (contains ":" $first) (eq $first "localhost")) -}}
    {{- fail (printf "policyManager.image: registry=%q AND repository=%q where repository's first slash-segment %q looks fully-qualified. Set image.registry='' OR set image.repository to a host-less path. See NOTES.txt." .Values.policyManager.image.registry .Values.policyManager.image.repository $first) -}}
  {{- end -}}
{{- end -}}
{{- if and .Values.dashboard.enabled (ne (.Values.dashboard.image.registry | default "") "") -}}
  {{- $first := (split "/" .Values.dashboard.image.repository)._0 -}}
  {{- if or (contains "." $first) (or (contains ":" $first) (eq $first "localhost")) -}}
    {{- fail (printf "dashboard.image: registry=%q AND repository=%q where repository's first slash-segment %q looks fully-qualified. Set image.registry='' OR set image.repository to a host-less path. See NOTES.txt." .Values.dashboard.image.registry .Values.dashboard.image.repository $first) -}}
  {{- end -}}
{{- end -}}
{{- if and .Values.admissionWebhook.enabled (not .Values.admissionWebhook.tls.autoGenerate) (not (and .Values.admissionWebhook.tls.caCert .Values.admissionWebhook.tls.cert .Values.admissionWebhook.tls.key)) -}}
  {{- /* The render-time fail in admission-webhook-tls.yaml is the actual guard. This is a friendlier pre-render check. */ -}}
{{- end -}}
{{- end -}}

