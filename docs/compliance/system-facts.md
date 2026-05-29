# System Facts Sheet (authoritative source for compliance artifacts)

> **Status:** Living reference · **Generated:** 2026-05-29 · **Owner role:** System Owner (TBD — assign before assessment)
>
> This sheet pins the **canonical system facts, asset IDs, ports, and trust zones** that every
> `docs/compliance/` artifact must use verbatim so the SSP, boundary diagram, inventory, CRM, and
> control matrix stay mutually consistent. Sourced from the code (`cmd/`, `internal/config`,
> `charts/kube-policies`, `deployments/kubernetes/crds`) and `README.md`. It feeds the SSP
> system-description section (see [ssp/SSP.md](ssp/SSP.md)).

## System identification

- **System name:** Kube-Policies (Kubernetes admission-control & policy-management)
- **System abbreviation:** KP
- **Repository:** `github.com/Jibbscript/kube-policies`
- **Deployment model:** Helm chart (`charts/kube-policies`) into a single Kubernetes namespace (`kube-policies-system`) on a customer/CSP-provided cluster.
- **Categorization (target):** FIPS-199 **Moderate** (see [categorization/FIPS-199.md](categorization/FIPS-199.md)).

## Components and canonical asset IDs

| Asset ID | Component | Language/Kind | Listening ports (current) | Boundary | Source |
|---|---|---|---|---|---|
| `AST-WH` | admission-webhook | Go service | `8443/tcp` TLS 1.3 (`/validate`,`/mutate`); `9090/tcp` HTTP metrics | In-boundary | `cmd/admission-webhook/main.go` |
| `AST-PM` | policy-manager | Go service | `8080/tcp` HTTP REST `/api/v1`; `9091/tcp` HTTP metrics | In-boundary | `cmd/policy-manager/main.go` |
| `AST-DB` | dashboard BFF | Go service | `8090/tcp` HTTP (SPA + `/api` + reverse-proxy `/api/v1`→`AST-PM:8080`); `9092/tcp` HTTP metrics | In-boundary | `cmd/dashboard/main.go` |
| `AST-SPA` | Svelte dashboard SPA | Static assets embedded in `AST-DB` | (served by `AST-DB:8090`) | In-boundary | `web/`, `cmd/dashboard/web_embed.go` |
| `AST-OPA` | OPA/Rego policy evaluator | Embedded Go library (in `AST-WH` and `AST-PM`) | n/a | In-boundary | `internal/policy/engine.go` |
| `AST-CRD-POL` | `Policy` CRD | Namespaced CustomResourceDefinition | n/a (kube-apiserver stored) | In-boundary (data) | `deployments/kubernetes/crds/policies.yaml` |
| `AST-CRD-EXC` | `PolicyException` CRD | Namespaced CustomResourceDefinition | n/a (kube-apiserver stored) | In-boundary (data) | `deployments/kubernetes/crds/policyexceptions.yaml` |
| `AST-CHART` | Helm chart + RBAC/Services/Config | Deployment artifact | n/a | In-boundary | `charts/kube-policies/` |

### Container images

| Asset ID | Image (logical) | Built by | Notes |
|---|---|---|---|
| `AST-IMG-WH` | `admission-webhook` | `build/docker`, `make docker-build-admission-webhook` | distroless base |
| `AST-IMG-PM` | `policy-manager` | `make docker-build-policy-manager` | distroless base |
| `AST-IMG-DB` | `dashboard` | `make docker-dashboard` | requires `ui-build` |

> Image registry/tag/digest are operator-supplied (chart is registry-agnostic). Versioning/pinning is addressed in phase P6.

## Ports / protocols / services (authoritative)

| Port | Asset | Purpose | Transport (current) | Target state |
|---|---|---|---|---|
| `8443/tcp` | `AST-WH` | AdmissionReview `/validate`, `/mutate` | TLS 1.3, **no client-cert auth** | mTLS to apiserver (P3) |
| `9090/tcp` | `AST-WH` | Prometheus metrics | **HTTP, unauthenticated** | TLS+authn (P3) |
| `8080/tcp` | `AST-PM` | REST API `/api/v1/*` | **HTTP, unauthenticated** | TLS 1.3 + OIDC/authZ (P2/P3) |
| `9091/tcp` | `AST-PM` | Prometheus metrics | **HTTP, unauthenticated** | TLS+authn (P3) |
| `8090/tcp` | `AST-DB` | SPA + `/api` + reverse-proxy | **HTTP, no user authn** (write-gated by `ALLOW_WRITES`) | TLS + OIDC login (P3) |
| `9092/tcp` | `AST-DB` | Prometheus metrics | **HTTP, unauthenticated** | TLS+authn (P3) |

## Trust zones

- `ZONE-EXT` — outside the authorization boundary: kube-apiserver, Prometheus scraper, cluster operators/users, the hosting CSP control plane and infrastructure.
- `ZONE-SYS` — inside the authorization boundary: the `kube-policies-system` namespace workloads (`AST-WH`, `AST-PM`, `AST-DB`/`AST-SPA`) and the namespaced CRDs (`AST-CRD-POL`, `AST-CRD-EXC`).

## External interconnections (current transport)

| ID | From → To | Data | Sensitivity | Protocol (current) | Protection target |
|---|---|---|---|---|---|
| `ICX-01` | kube-apiserver (`ZONE-EXT`) → `AST-WH:8443` | AdmissionReview request/response | Moderate (object specs) | TLS 1.3, server-auth only | + apiserver mTLS (P3) |
| `ICX-02` | `AST-WH` → `AST-PM:8080` `/api/v1/decisions/internal` | Admission decision records + bearer token | Moderate | **HTTP + static bearer token** | TLS + audience-bound token (P3/P4) |
| `ICX-03` | Prometheus (`ZONE-EXT`) → `:9090/:9091/:9092` | Operational metrics | Low–Moderate | **HTTP, unauthenticated** | TLS+authn (P3) |
| `ICX-04` | `AST-DB` → `AST-PM:8080` (`/api/v1`, decisions stream) | Policy data, decision feed | Moderate | **HTTP** | TLS (P4) |
| `ICX-05` | Operators/users (`ZONE-EXT`) → `AST-DB:8090` | Dashboard UI / API | Moderate | **HTTP, no user authn** | TLS + OIDC (P3) |
| `ICX-06` | `AST-PM` ↔ kube-apiserver (`ZONE-EXT`) | `Policy`/`PolicyException` CRD reconcile, Lease | Moderate | kubeconfig/SA token (in-cluster TLS) | least-priv SA (P3) |

## Information types (FIPS-199 / SP 800-60 basis)

- **IT-1 Configuration & policy data** — `Policy`/`PolicyException` CRDs, Helm values, Rego rules.
- **IT-2 Admission decision audit records** — allow/deny decisions, attribution, suppression (`internal/audit`).
- **IT-3 Operational metrics** — Prometheus exposition.

## Security-relevant defaults (current, for the secure-config baseline)

- Webhook TLS minimum version pinned to 1.3 (`internal/config`).
- Admission `failure_mode` validated to `fail-open|fail-closed`; default ships **fail-closed**.
- Dashboard **read-only** unless `ALLOW_WRITES=true` (`cmd/dashboard/proxy.go`).
- Audit backend validated to `file|stdout`.
- Bright-spot hardening already present: dashboard pod `runAsNonRoot`, `allowPrivilegeEscalation:false`, `readOnlyRootFilesystem` (`charts/.../dashboard-deployment.yaml`); leader election in policy-manager; distroless images.

> Known foundational gaps (no FIPS module, unauthenticated planes, no NetworkPolicy, `spec.template.spec` enforcement blindness, audit on `emptyDir`, untrustworthy CI) are tracked in [POAM.md](POAM.md) and remediated across phases P1–P12 (`.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`).
