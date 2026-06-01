---
title: "System & Communications Protection Procedures (SC) — Kube-Policies (KP)"
control_family: "SC — System and Communications Protection"
controls: "SC-1, SC-5, SC-7, SC-7(3), SC-7(4), SC-7(5), SC-7(7), SC-8, SC-8(1), SC-12, SC-13, SC-17"
version: "0.2.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# System & Communications Protection Procedures — Kube-Policies (KP)

These are the operational procedures that implement the System and Communications
Protection policy (`docs/compliance/policies/SC-policy.md`) for the Kube-Policies system
(KP). They cover how the TLS 1.3 floor is enforced and verified, how serving certificates
and keys are managed and rotated, and how the FIPS-validated cryptographic posture is
confirmed.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (no ATO). These procedures describe what is *actually implemented*
in the shipped code and Helm chart and what an assessor or operator can run to verify it.
Where a control is Partial or Planned, the procedure says so; open weaknesses are tracked
in `poam.csv` and the phased plan `.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** These procedures are reviewed and updated at least **annually** (next
review **2027-05-31**) and whenever a significant change to the system, its boundary, its
TLS/crypto configuration, or its certificate management occurs. Reviews are recorded by
updating the `last_reviewed`/`next_review` front-matter and the version.

## 1 Scope

These procedures apply to the TLS-serving and cryptographic surfaces of the in-boundary
components in the `kube-policies-system` namespace: the admission-webhook (`AST-WH`,
`8443/tcp`), the policy-manager (`AST-PM`, `8080/tcp`), the dashboard (`AST-DB`,
`8090/tcp`), and the metrics endpoints (`9090/9091/9092`), as pinned in `system-facts.md`.
The approved algorithm/key-strength matrix these procedures enforce is defined in
`crypto-standards.md`; the validated module backing all crypto is recorded in
`crypto-module.md`.

## 2 TLS 1.3 enforcement verification (SC-8 / SC-8(1))

### 2.1 What enforces the floor

The TLS floor is enforced in code, not by convention. `internal/config/tls.go`
(`BuildServerTLSConfig` / `Validate`) **rejects any `min_version` below 1.3 at load time**
and rejects any non-approved cipher-suite name, so a weak floor can never reach a
listener. TLS 1.3 cipher suites are fixed by the Go runtime and are not operator-tunable.

### 2.2 Build-gating conformance test (primary evidence)

The authoritative, automated proof is the hermetic conformance test
`internal/config/tls_conformance_test.go`. It is deliberately placed in package `config` so
it runs under `go test ./internal/...` in CI and `make test-unit` (a test under `test/tls`
would be silently skipped). It asserts that a server built from `BuildServerTLSConfig`:

- **refuses** TLS 1.0, 1.1, and 1.2 handshakes;
- **completes** a TLS 1.3 handshake and negotiates exactly TLS 1.3;
- contains **no insecure cipher** in the allow-list (guarded against Go's
  `tls.InsecureCipherSuites()`); and
- never lets the validated version floor regress below TLS 1.3.

Run it:

```console
go test ./internal/config/ -run TestConformance -v
# or the full unit suite that CI gates on:
make test-unit
```

A green run is the SC-8/SC-8(1) enforcement evidence. The approved algorithm/key-strength
matrix it complements is in `crypto-standards.md`.

### 2.3 Live verification against a running listener

To confirm the floor on a deployed pod (assessor spot-check), negotiate against each
TLS listener and confirm 1.3 succeeds while 1.2 is refused:

```console
# webhook :8443 — expect "Protocol  : TLSv1.3"
kubectl -n kube-policies-system port-forward svc/<release>-admission-webhook 8443:8443 &
echo | openssl s_client -connect 127.0.0.1:8443 -tls1_3 2>/dev/null | grep -E 'Protocol|Cipher'
# A TLS 1.2 attempt MUST fail the handshake:
echo | openssl s_client -connect 127.0.0.1:8443 -tls1_2 2>/dev/null | grep -E 'Protocol|no peer'
```

Repeat for policy-manager `8080/tcp` (TLS 1.3 via `BuildServerTLSConfig`) and, when
enabled, the dashboard `8090/tcp`. When `metrics.tls.enabled`, the webhook (`9090`) and
policy-manager (`9091`) `/metrics` additionally require a bearer token; the dashboard
`/metrics` (`9092`) is TLS-gated on `dashboard.tls.enabled` and is not bearer-authenticated
(tracked gap).

### 2.4 Mutual TLS (SC-8(1)) when enabled

When the webhook is run with `--client-ca-path` (sourced from Secret
`<release>-admission-webhook-client-ca` / `admissionWebhook.tls.clientCA`), it
**requires and verifies** a client certificate on `8443/tcp`. Confirm enforcement: a
handshake without a client cert must be rejected; the webhook logs `mtls_enforced=true`
at startup. If `--client-ca-path` is unset the webhook runs server-auth-only (permissive)
and logs a warning — this is the documented default and a tracked gap, not a silent
failure.

## 2A SC-7 — NetworkPolicy / network-segmentation verification

The full design and the every-flow→template map are in
`docs/compliance/network-architecture.md`. The NetworkPolicy objects ship in the chart
(`charts/kube-policies/templates/networkpolicy-*.yaml`, `networkPolicy.enabled` default true)
and in the static base manifest (`deployments/kubernetes/base/networkpolicy.yaml`), but they
**enforce nothing unless the CNI implements NetworkPolicy**.

### 2A.1 Confirm the CNI enforces NetworkPolicy (PREREQUISITE — CIS 5.3.1)

Do this first; if it fails, the policies below are inert and SC-7 segmentation is **not**
in effect regardless of what `kubectl get networkpolicy` shows.

```console
kubectl create ns np-test
kubectl -n np-test run a --image=busybox --restart=Never -- sleep 3600
kubectl -n np-test run b --image=busybox --restart=Never -- sleep 3600
kubectl -n np-test wait --for=condition=Ready pod/a pod/b
kubectl -n np-test apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: deny-all, namespace: np-test }
spec: { podSelector: {}, policyTypes: [Ingress, Egress] }
EOF
# Enforcing CNI (Calico/Cilium/Antrea) -> TIMES OUT (blocked, expected).
# Non-enforcing CNI (kindnet) -> SUCCEEDS (NOT enforced — segmentation inert).
kubectl -n np-test exec a -- wget -qO- --timeout=3 \
  "http://$(kubectl -n np-test get pod b -o jsonpath='{.status.podIP}')"
kubectl delete ns np-test
```

### 2A.2 Confirm the policy set rendered and is fail-closed where expected

```console
# With the dashboard enabled, expect the default-deny baseline plus the least-privilege
# allow-list (11 NetworkPolicy objects):
kubectl -n kube-policies-system get networkpolicy
# Default-deny baseline selects every pod with no allow rules:
kubectl -n kube-policies-system get networkpolicy <release>-default-deny -o yaml \
  | grep -A3 'policyTypes'
# Fail-closed-until-configured: with networkPolicy.apiServerCIDRs / webhook.ingressFrom empty,
# the egress-apiserver and ingress-webhook policies render with NO peers (deny). Setting the
# control-plane CIDRs is REQUIRED for leader election / TokenReview / admission to work.
```

A green CNI probe (2A.1) plus the rendered fail-closed/allow-list (2A.2) is the SC-7 /
SC-7(3)/(4)/(5)/(7) enforcement evidence. **Until 2A.1 is run on an enforcing CNI in the
target environment, report SC-7 as "Implemented (Helm) — requires enforcing CNI; live proof
pending", not as enforced.**

## 2B SC-5 — Denial-of-service protection verification

```console
# Rate-limit / body-cap / concurrency rejections increment this metric:
curl -s http://<pod>:<metrics-port>/metrics | grep kube_policies_http_rate_limited_total
# Exceed the body cap (default 3 MiB) -> HTTP 413:
head -c 4194304 /dev/zero | curl -s -o /dev/null -w '%{http_code}\n' \
  --data-binary @- http://<webhook>:8443/validate   # expect 413
# Flood beyond ~50 rps / burst 100 -> HTTP 429 (reason="rate"); saturate in-flight -> 429
# (reason="concurrency"); >100 concurrent SSE streams -> 429 (reason="stream_capacity").
```

The limits are configured via `rateLimit.*` (default on) and are **per replica**. The
optional namespace ResourceQuota/LimitRange (`resourceQuota.enabled` / `limitRange.enabled`)
ship **off by default**; when enabled, verify with
`kubectl -n kube-policies-system get resourcequota,limitrange`.

## 3 Certificate and key management / rotation (SC-12 / SC-17)

The authoritative rotation runbook is `docs/runbooks/cert-rotation.md`; the per-key
inventory and key-management plan are authored under CRY-WU-18 (`crypto-inventory.md`,
`key-management-plan.md`). The procedures below summarize the operational flow.

### 3.1 Webhook TLS bootstrap (how serving certs are provisioned)

Certificate provisioning is driven entirely by the Helm chart in `charts/kube-policies`:

- **Production (cert-manager).** With `certManager.enabled=true`, a shared self-signed root
  CA is bootstrapped by `charts/kube-policies/templates/issuer.yaml` and each component
  serving certificate is issued by `charts/kube-policies/templates/certificate.yaml` as an
  **ECDSA P-256** leaf (`privateKey.algorithm=ECDSA size=256`) into its own Secret. The
  `ValidatingWebhookConfiguration` `caBundle` is populated by cert-manager's
  `ca-injector` via the `cert-manager.io/inject-ca-from` annotation.
- **Bootstrap branches (no cert-manager).** When `certManager.enabled=false`,
  `charts/kube-policies/templates/admission-webhook-tls.yaml` provisions the serving Secret
  and inline `caBundle` via a three-branch render: (1) an existing Secret is preserved for
  upgrade idempotence; (2) operator-supplied inline `tls.caCert/cert/key`
  (`autoGenerate=false`); or (3) `autoGenerate=true`, which uses sprig
  `genCA`/`genSignedCert` to emit a **fixed RSA-2048 / SHA-256** pair. The autoGenerate path
  is **DEMO-ONLY** (below the FedRAMP-Moderate bar) and must not be used in production.
- **Fail-fast.** If no Secret exists, no inline PEM is supplied, and `autoGenerate=false`,
  the chart **fails the render** rather than installing a webhook with an empty `caBundle`.

For dev/demo outside Helm, `scripts/gen-webhook-cert.sh` generates an approved-strength
**ECDSA P-256** cert.

### 3.2 Rotation

- **cert-manager (production):** rotation is **automatic** — cert-manager renews each
  `Certificate` `renewBefore` expiry and writes new material into the serving Secret; the
  webhook/policy-manager/dashboard pick it up **without a restart** via the directory-watch
  hot reloader (`internal/tlsreload`). No action is needed unless renewal is failing; see
  `docs/runbooks/cert-rotation.md` for the diagnose/force-renew steps.
- **Demo / self-signed:** regenerate with `scripts/gen-webhook-cert.sh <namespace>` (or
  delete the cert Secret and `helm upgrade`); the reloader serves the new cert with no
  restart.
- **Internal bearer token rotation:** uses a **two-token window** (old + new accepted
  simultaneously) so `AST-WH → AST-PM` does not break mid-rotation; see
  `docs/runbooks/internal-token-rotation.md`.

### 3.3 Rotation verification

After any rotation, confirm the served key still meets `crypto-standards.md` and that the
expiry gauge advances:

```console
# Key algorithm / curve / signature must match the approved matrix:
kubectl -n kube-policies-system get secret <release>-admission-webhook-certs \
  -o jsonpath='{.data.tls\.crt}' | base64 -d \
  | openssl x509 -text -noout | grep -E 'NIST CURVE|Signature Algorithm'
# Expected (approved): NIST CURVE: P-256 / ecdsa-with-SHA256
```

The TLS expiry gauge `kube_policies_tls_cert_expiry_seconds{component=...}` should jump
forward and the `KubePoliciesCertExpiringSoon` / `KubePoliciesCertExpired` alerts should
resolve within one evaluation interval (cert-manager Secret propagation is eventually
consistent, up to ~1 minute). The reloader logs `certificate reloaded` on pickup.

## 4 FIPS cryptographic posture verification (SC-13)

KP cryptography runs through the FIPS 140-3 Go Cryptographic Module recorded in
`crypto-module.md`. Verify both build provenance and runtime enforcement:

```console
# Build provenance — the binary was compiled against the validated module:
go version -m dist/admission-webhook-linux-amd64 | grep -E 'GOFIPS140|DefaultGODEBUG'
# Expect: GOFIPS140=v1.0.0  and  DefaultGODEBUG=fips140=on
# CI gates this via the fips-verify job (make verify-fips).
```

Runtime enforcement is provided by the startup self-test in `internal/cryptofips`
(`MustEnforce`): when `REQUIRE_FIPS=true` (production Helm values) but the module is not
active, the process **aborts** before opening any listener. Confirm the boot log line
`FIPS 140-3 self-test` shows `fips_enabled=true` and `fips_required=true` on production
pods.

> **CMVP certificate is `REQUIRES VERIFICATION`.** The exact CMVP certificate number for
> the Go Cryptographic Module v1.0.0 is not yet confirmed; the System Owner must record it
> in `crypto-module.md` before SC-13 is submitted as ATO evidence. Do not assert a specific
> certificate number until then.

## 5 Audit-record integrity verification (SC-8 integrity / AU-9)

Transmission and storage integrity of audit records is enforced by an HMAC-SHA256 hash
chain (`internal/audit/integrity.go`), keyed from Secret `<release>-audit-integrity`. The
chain is verifiable offline: `VerifyChain` recomputes the HMAC over the verbatim persisted
bytes and reports the first record whose sequence, prev-hash, or HMAC does not match. A
non-empty error from chain verification indicates tampering and is a finding to triage.

## 6 Records and review

Evidence produced by these procedures (conformance-test output, `openssl`/`kubectl`
verification captures, FIPS build/boot logs) is retained as SC assessment evidence and
referenced from the SSP (`ssp/SSP.md`). These procedures are reviewed at least annually
(next review **2027-05-31**) and on any significant change per §0.

## 7 References

- SC policy: `docs/compliance/policies/SC-policy.md`
- Network boundary & segmentation architecture (SC-7/CA-3): `docs/compliance/network-architecture.md`
- NetworkPolicy templates: `charts/kube-policies/templates/networkpolicy-*.yaml` · static base: `deployments/kubernetes/base/networkpolicy.yaml`
- Rate-limit / DoS middleware (SC-5): `internal/middleware/ratelimit.go`
- Cert rotation runbook: `docs/runbooks/cert-rotation.md` · Internal-token rotation: `docs/runbooks/internal-token-rotation.md`
- Cryptographic module (SC-13): `crypto-module.md` · Cryptographic standards (SC-12/13/17): `crypto-standards.md`
- TLS conformance test: `internal/config/tls_conformance_test.go` · TLS config: `internal/config/tls.go` · Hot reload: `internal/tlsreload`
- Webhook TLS bootstrap: `charts/kube-policies/templates/admission-webhook-tls.yaml`, `charts/kube-policies/templates/certificate.yaml`, `charts/kube-policies/templates/issuer.yaml` · `scripts/gen-webhook-cert.sh`
- FIPS self-test: `internal/cryptofips/fips.go` · Audit integrity: `internal/audit/integrity.go`
- System facts: `system-facts.md` · Compliance index: [README](../README.md)
- NIST SP 800-53 Rev 5 (SC-5, SC-7, SC-7(3)(4)(5)(7), SC-8, SC-8(1), SC-12, SC-13, SC-17, CA-3); FedRAMP Moderate baseline; CIS Kubernetes 5.3.1/5.3.2; FIPS 140-3.
