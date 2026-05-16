#!/usr/bin/env bash
# gen-webhook-cert.sh — generate a self-signed TLS cert for the
# kube-policies admission webhook and create the Secret the chart mounts.
#
# Usage: scripts/gen-webhook-cert.sh <namespace>
#
# The cert lives only inside the kind cluster; it is regenerated on every
# `make demo-up`. The Subject Alternative Names match the in-cluster
# Service DNS names so the webhook can use them as both server name and
# certificate identity. This script is for the demo flow ONLY — production
# deployments should source certs from cert-manager or another PKI.
set -euo pipefail

NAMESPACE="${1:?usage: $0 <namespace>}"
RELEASE_NAME="${RELEASE_NAME:-kube-policies}"
SERVICE_NAME="${SERVICE_NAME:-${RELEASE_NAME}-admission-webhook}"
SECRET_NAME="${SECRET_NAME:-${SERVICE_NAME}-certs}"

TMPDIR="$(mktemp -d -t kube-policies-webhook-cert.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

KEY="$TMPDIR/tls.key"
CERT="$TMPDIR/tls.crt"
CONF="$TMPDIR/openssl.cnf"

cat >"$CONF" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[req_distinguished_name]
CN = ${SERVICE_NAME}.${NAMESPACE}.svc

[v3_req]
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

openssl req -new -newkey rsa:2048 -nodes -x509 -days 365 \
  -config "$CONF" -extensions v3_req \
  -keyout "$KEY" -out "$CERT" >/dev/null 2>&1

# Create or update the Secret idempotently.
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
  --from-file=tls.crt="$CERT" \
  --from-file=tls.key="$KEY" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo "OK: TLS Secret $NAMESPACE/$SECRET_NAME (CN=${SERVICE_NAME}.${NAMESPACE}.svc)"
