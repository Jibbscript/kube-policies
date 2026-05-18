#!/usr/bin/env bash
# gen-webhook-cert.sh — generate a self-signed CA and signed leaf cert
# for the kube-policies admission webhook, and create the Secret the
# chart mounts.
#
# Usage: scripts/gen-webhook-cert.sh <namespace>
#
# The cert chain lives only inside the kind cluster; it is regenerated
# on every `make demo-up`. The Subject Alternative Names match the
# in-cluster Service DNS names so the webhook can use them as both
# server name and certificate identity. The Secret has three keys:
#   - tls.crt  — leaf certificate served by the webhook
#   - tls.key  — leaf private key
#   - ca.crt   — issuing CA cert; the chart's
#                ValidatingWebhookConfiguration mounts this as caBundle
#
# This script is for the demo flow ONLY — production deployments should
# source certs from cert-manager or another PKI that issues both a CA
# and signed leaf.
set -euo pipefail

NAMESPACE="${1:?usage: $0 <namespace>}"
RELEASE_NAME="${RELEASE_NAME:-kube-policies}"
SERVICE_NAME="${SERVICE_NAME:-${RELEASE_NAME}-admission-webhook}"
SECRET_NAME="${SECRET_NAME:-${SERVICE_NAME}-certs}"

TMPDIR="$(mktemp -d -t kube-policies-webhook-cert.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

CA_KEY="$TMPDIR/ca.key"
CA_CERT="$TMPDIR/ca.crt"
LEAF_KEY="$TMPDIR/tls.key"
LEAF_CSR="$TMPDIR/tls.csr"
LEAF_CERT="$TMPDIR/tls.crt"
LEAF_CONF="$TMPDIR/openssl.cnf"
EXT_CONF="$TMPDIR/v3.ext"

cat >"$LEAF_CONF" <<EOF
[req]
distinguished_name = req_distinguished_name
prompt             = no

[req_distinguished_name]
CN = ${SERVICE_NAME}.${NAMESPACE}.svc
EOF

cat >"$EXT_CONF" <<EOF
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt_names

[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
DNS.5 = localhost
IP.1  = 127.0.0.1
EOF

# 1. Issuing CA — self-signed, used as caBundle in the VWC.
openssl req -new -newkey rsa:2048 -nodes -x509 -days 365 \
  -subj "/CN=kube-policies-webhook-ca" \
  -keyout "$CA_KEY" -out "$CA_CERT" >/dev/null 2>&1

# 2. Leaf key + CSR (CN = service FQDN).
openssl req -new -newkey rsa:2048 -nodes \
  -config "$LEAF_CONF" \
  -keyout "$LEAF_KEY" -out "$LEAF_CSR" >/dev/null 2>&1

# 3. CA-signed leaf cert with the SAN extensions baked in.
openssl x509 -req -in "$LEAF_CSR" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$LEAF_CERT" -days 365 -sha256 \
  -extfile "$EXT_CONF" >/dev/null 2>&1

# Create or update the Secret idempotently.
# Two compatibility constraints with the chart's helm-rendered Secret:
#   1. Helm adoption: stamp app.kubernetes.io/managed-by + meta.helm.sh/*
#      so `helm upgrade --install $RELEASE_NAME` adopts (rather than refuses
#      to import) the pre-generated cert material.
#   2. Type must match: the chart renders type=kubernetes.io/tls; Secret.type
#      is immutable, so creating as the default Opaque here causes helm to
#      error with "type: Invalid value: \"kubernetes.io/tls\": field is
#      immutable". `kubectl create secret tls` covers tls.crt + tls.key but
#      not ca.crt — assemble the manifest manually to ship all three keys.
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

TLS_CRT_B64="$(base64 < "$LEAF_CERT" | tr -d '\n')"
TLS_KEY_B64="$(base64 < "$LEAF_KEY"  | tr -d '\n')"
CA_CRT_B64="$(base64 < "$CA_CERT"    | tr -d '\n')"

kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: ${SECRET_NAME}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/managed-by: Helm
  annotations:
    meta.helm.sh/release-name: ${RELEASE_NAME}
    meta.helm.sh/release-namespace: ${NAMESPACE}
data:
  tls.crt: ${TLS_CRT_B64}
  tls.key: ${TLS_KEY_B64}
  ca.crt: ${CA_CRT_B64}
EOF

echo "OK: TLS Secret $NAMESPACE/$SECRET_NAME (CN=${SERVICE_NAME}.${NAMESPACE}.svc, ca.crt + tls.crt + tls.key)"
