# Runbook — TLS Certificate Rotation & Expiry Alerts

**Applies to:** the admission-webhook (:8443/:9090), policy-manager (:8080/:9091),
and dashboard (:8090/:9092) serving certificates.
**Controls:** SC-12, SC-17, SI-4 (CRY-WU-10/11/12).
**Alerts:** `KubePoliciesCertExpiringSoon` (warning, <7 days), `KubePoliciesCertExpired` (critical).

## Signal

Each TLS server publishes `kube_policies_tls_cert_expiry_seconds{component=...}`
— the served certificate's expiry as Unix seconds, refreshed on every hot
reload (CRY-WU-12). The Prometheus rules in
`monitoring/prometheus/rules/kube-policies-tls.yml` alert as expiry approaches.

## Diagnose

```console
# How long until each served cert expires (seconds):
#   kube_policies_tls_cert_expiry_seconds - time()
kubectl -n kube-policies-system get pods -l app.kubernetes.io/name=kube-policies
# Inspect the mounted cert directly:
kubectl -n kube-policies-system exec deploy/<release>-admission-webhook -- \
  sh -c 'cat /etc/certs/tls.crt' | openssl x509 -noout -enddate -subject
```

## Rotate

**cert-manager (production, certManager.enabled=true):** rotation is automatic —
cert-manager renews each Certificate `renewBefore` its expiry and writes the new
material into the serving Secret. The webhook/policy-manager/dashboard pick it up
**without a restart** via the hot reloader (CRY-WU-10, directory watch on the
`..data` symlink swap). No action needed unless renewal is failing:

```console
kubectl -n kube-policies-system get certificate
kubectl -n kube-policies-system describe certificate <release>-admission-webhook
# Force-renew:
kubectl -n kube-policies-system delete secret <release>-admission-webhook-certs
```

**Demo / self-signed (certManager.enabled=false):** regenerate and the reloader
serves the new cert with no restart:

```console
scripts/gen-webhook-cert.sh kube-policies-system     # ECDSA P-256 (CRY-WU-11)
# or: delete the cert Secret and helm upgrade to re-render it.
```

## Verify

```console
# The expiry gauge should jump forward after rotation:
#   kube_policies_tls_cert_expiry_seconds - time()  >> 7d
# and the alert should resolve within one evaluation interval.
```

The reloader serves the new certificate on the next TLS handshake; existing
connections are unaffected. If the alert does not clear, confirm the pod's
mounted Secret actually updated (cert-manager Secret propagation to the kubelet
is eventually consistent, up to ~1 minute) and that the reloader logged
`certificate reloaded`.
