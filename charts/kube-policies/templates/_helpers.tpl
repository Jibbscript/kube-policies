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
Per-component ServiceAccount name helpers live below (IAM-WU-09). The former shared
"kube-policies.serviceAccountName" helper was removed: collapsing the webhook and
policy-manager onto one identity would undo the separation of duties.
*/}}

{{/*
Create the name of the admission webhook
*/}}
{{- define "kube-policies.admissionWebhookName" -}}
{{- printf "%s-admission-webhook" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the name of the admission-webhook ServiceAccount (IAM-WU-09). Separation of
duties: the enforcement plane gets its own identity, distinct from the management
plane. Honors an optional override at rbac.serviceAccount.webhookName, else defaults
to <fullname>-admission-webhook.
*/}}
{{- define "kube-policies.webhookServiceAccountName" -}}
{{- $sa := .Values.rbac.serviceAccount | default dict -}}
{{- default (printf "%s-admission-webhook" (include "kube-policies.fullname" .)) $sa.webhookName }}
{{- end }}

{{/*
Create the name of the policy-manager ServiceAccount (IAM-WU-09). Honors an optional
override at rbac.serviceAccount.policyManagerName, else defaults to
<fullname>-policy-manager.
*/}}
{{- define "kube-policies.policyManagerServiceAccountName" -}}
{{- $sa := .Values.rbac.serviceAccount | default dict -}}
{{- default (printf "%s-policy-manager" (include "kube-policies.fullname" .)) $sa.policyManagerName }}
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
Create the policy-manager TLS certificate secret name (CRY-WU-05)
*/}}
{{- define "kube-policies.policyManagerCertSecretName" -}}
{{- printf "%s-policy-manager-certs" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the dashboard TLS certificate secret name (CRY-WU-07)
*/}}
{{- define "kube-policies.dashboardCertSecretName" -}}
{{- printf "%s-dashboard-certs" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the admission-webhook CLIENT certificate secret name (IAM-WU-03). This is
the identity the webhook PRESENTS to the policy-manager for mutual TLS — distinct
from its serving cert (certSecretName) and the apiserver client-CA bundle.
*/}}
{{- define "kube-policies.webhookClientCertSecretName" -}}
{{- printf "%s-admission-webhook-client-certs" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the dashboard CLIENT certificate secret name (IAM-WU-03): the identity the
dashboard PRESENTS to the policy-manager for mutual TLS on the proxied API + SSE.
*/}}
{{- define "kube-policies.dashboardClientCertSecretName" -}}
{{- printf "%s-dashboard-client-certs" (include "kube-policies.fullname" .) }}
{{- end }}

{{/*
Create the config map name
*/}}
{{- define "kube-policies.configMapName" -}}
{{- printf "%s-config" (include "kube-policies.fullname" .) }}
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

Inputs: a dict with keys {registry, repository, tag, defaultTag, digest}.

CFG-WU-10 (CM-2/CM-5/SI-7): when a non-empty "digest" is supplied the image is
pinned by immutable digest (repository@sha256:...) and the mutable tag is
intentionally dropped — this is the recommended production posture. A digest may
be given bare (hash only) or sha256:-prefixed; both render as @sha256:<hash>.
With no digest, the behavior is unchanged (repository:tag).
*/}}
{{- define "kube-policies.image" -}}
{{- $registry := .registry | default "" -}}
{{- $repository := required "kube-policies.image: repository is required" .repository -}}
{{- $digest := .digest | default "" -}}
{{- $first := (split "/" $repository)._0 -}}
{{- $qualified := or (contains "." $first) (or (contains ":" $first) (eq $first "localhost")) -}}
{{- $name := $repository -}}
{{- if not (or (eq $registry "") $qualified) -}}
{{- $name = printf "%s/%s" $registry $repository -}}
{{- end -}}
{{- if $digest -}}
{{- $ref := $digest -}}
{{- if not (contains ":" $digest) -}}
{{- $ref = printf "sha256:%s" $digest -}}
{{- end -}}
{{ $name }}@{{ $ref }}
{{- else -}}
{{ $name }}:{{ .tag | default .defaultTag }}
{{- end -}}
{{- end -}}

{{/*
Internal-auth mode for the webhook -> policy-manager decisions channel (IAM-WU-11).
"tokenreview" (default): the webhook presents an audience-bound projected
ServiceAccount token validated via the Kubernetes TokenReview API. "static": the
documented escape hatch using the shared bearer token (non-cluster/demo only).
*/}}
{{- define "kube-policies.internalAuthMode" -}}
{{- dig "internalAuth" "mode" "tokenreview" .Values.policyManager -}}
{{- end -}}

{{/*
Expected audience for the projected token (IAM-WU-11). Dedicated to this channel;
NOT reused from the OIDC audience config. Default "policy-manager".
*/}}
{{- define "kube-policies.internalAuthAudience" -}}
{{- dig "internalAuth" "audience" "policy-manager" .Values.policyManager -}}
{{- end -}}

{{/*
Validate required values
*/}}
{{- define "kube-policies.validateValues" -}}
{{- /* Internal-auth mode guards (IAM-WU-11). */ -}}
{{- $internalMode := include "kube-policies.internalAuthMode" . -}}
{{- if not (has $internalMode (list "tokenreview" "static")) -}}
{{- fail (printf "policyManager.internalAuth.mode=%q is invalid; must be one of: tokenreview, static (IAM-WU-11)" $internalMode) -}}
{{- end -}}
{{- if eq $internalMode "tokenreview" -}}
  {{- if eq (include "kube-policies.internalAuthAudience" .) "" -}}
  {{- fail "policyManager.internalAuth.audience must be non-empty when policyManager.internalAuth.mode=tokenreview (IAM-WU-11): the projected token and the policy-manager's expected audience must match" -}}
  {{- end -}}
  {{- /* expirationSeconds < 600: the kubelet silently clamps projected token TTLs
       to its floor of 600s, making a <600 configuration misleading and contradicting
       the "<=1h" short-TTL posture. Fail early so the operator's intent is explicit.
       Default 3600 is well above the floor (FIX 7). */ -}}
  {{- $expSecs := dig "internalAuth" "expirationSeconds" 3600 .Values.policyManager | int -}}
  {{- if lt $expSecs 600 -}}
  {{- fail (printf "policyManager.internalAuth.expirationSeconds=%d is below the kubelet's minimum of 600s; the kubelet would silently clamp it, making the configured TTL misleading. Set expirationSeconds >= 600 (default: 3600, i.e. 1h)" $expSecs) -}}
  {{- end -}}
  {{- /* rbac.create and automountServiceAccountToken are prerequisites for the
       policy-manager's TokenReview call — only relevant when the PM is deployed.
       A webhook-only install (policyManager.enabled=false) with rbac.create=false
       or automount=false is valid; do NOT fail such renders (FIX 2). */ -}}
  {{- if .Values.policyManager.enabled -}}
    {{- if not .Values.rbac.create -}}
    {{- fail "policyManager.internalAuth.mode=tokenreview requires rbac.create=true (IAM-WU-11): the policy-manager needs the tokenreviews:create grant to validate inbound tokens. Set rbac.create=true or use internalAuth.mode=static." -}}
    {{- end -}}
    {{- if not (dig "automountServiceAccountToken" true .Values.policyManager) -}}
    {{- fail "policyManager.internalAuth.mode=tokenreview requires policyManager.automountServiceAccountToken=true (IAM-WU-11): the policy-manager calls the apiserver TokenReview API with its own SA token. Keep automount on or use internalAuth.mode=static." -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
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

{{/*
FIPS 140-3 runtime environment (CRY-WU-01, CRY-WU-02).
Emits GODEBUG so the validated module is active at runtime and, when
fips.required is true, REQUIRE_FIPS=true so each binary's startup self-test
aborts when the FIPS module is not active. Guarded with a default dict so the
chart still renders if the fips block is omitted.
*/}}
{{- define "kube-policies.fipsEnv" -}}
{{- $fips := .Values.fips | default dict -}}
- name: GODEBUG
  value: {{ $fips.godebug | default "fips140=on" | quote }}
{{- if $fips.required }}
- name: REQUIRE_FIPS
  value: "true"
{{- end }}
{{- end -}}
