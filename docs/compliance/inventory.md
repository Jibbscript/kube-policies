---
title: "Component Inventory"
control_family: "CM — Configuration Management"
version: "0.2.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Component Inventory — Kube-Policies (KP)

This inventory enumerates every component of the Kube-Policies system (in-boundary workloads,
data objects, deployment artifacts) and the external dependencies it relies on. It is the
machine-readable companion to [inventory.csv](inventory.csv) and is derived verbatim from the
authoritative [system facts sheet](system-facts.md). The categorization target is FIPS-199
**Moderate** under NIST SP 800-53 Rev 5 / FedRAMP Moderate.

> **Asset IDs match the boundary diagram.** The `AST-*` identifiers used here are the same
> identifiers drawn in the [authorization boundary diagram](diagrams/authorization-boundary.md)
> and pinned in the [system facts sheet](system-facts.md). These IDs feed the system-description
> section of the [System Security Plan](ssp/SSP.md); do not introduce alternative IDs in any
> artifact.

> **Annual review.** This inventory is reviewed at least annually (next review 2027-05-29) and
> whenever a component, port, image, or external interconnection changes.

## Boundary classification

- **In-Boundary** — components deployed and operated as part of Kube-Policies inside the
  `kube-policies-system` namespace (trust zone `ZONE-SYS`).
- **Inherited** — security controls satisfied by an underlying platform/provider (none of the
  components below are currently classified Inherited; platform services appear as External).
- **External** — dependencies in `ZONE-EXT` that are operator/CSP-supplied and outside the
  authorization boundary.

## In-boundary container images

The **Digest support** column records the digest-pinning capability (CM-2 / CM-8).
The `kube-policies.image` Helm helper (`charts/kube-policies/templates/_helpers.tpl`)
accepts a digest-bearing reference, so an operator can deploy a digest-pinned image
today by setting `*.image.tag` to a `tag@sha256:<digest>` value (rendering
`registry/repository:tag@sha256:<digest>`). The **shipped `values.yaml` still uses
floating tags** (`tag: "1.0.0"`, `pullPolicy: IfNotPresent`), so images are **not
digest-pinned by default** (residual **POAM-023**; digest-by-default is P6).

| Asset ID | Name | Image | Version | Digest support | Boundary | Notes |
|---|---|---|---|---|---|---|
| `AST-IMG-WH` | admission-webhook image | `admission-webhook` | operator-supplied (default tag `1.0.0`) | Supported (helper accepts `tag@sha256:…`); **not pinned by default** | In-Boundary | Distroless base; `make docker-build-admission-webhook`. |
| `AST-IMG-PM` | policy-manager image | `policy-manager` | operator-supplied (default tag `1.0.0`) | Supported (helper accepts `tag@sha256:…`); **not pinned by default** | In-Boundary | Distroless base; `make docker-build-policy-manager`. |
| `AST-IMG-DB` | dashboard image | `dashboard` | operator-supplied | Supported (helper accepts `tag@sha256:…`); **not pinned by default** | In-Boundary | Distroless base; `make docker-dashboard` (requires `ui-build`); embeds `AST-SPA`. |

> Image registry/tag/digest are operator-supplied (the chart is registry-agnostic).
> Per-release inventory currency (CM-8) is reviewed at each release; SBOM-driven
> auto-update and unauthorized-component detection (CM-8(1)/CM-8(3)) and
> digest-pinning by default + base-image pinning (`scripts/pin-base-images.sh`) are
> addressed in remediation phase **P6**.

## In-boundary services and components

| Asset ID | Name | Type | Image | Ports | Protocols | Boundary |
|---|---|---|---|---|---|---|
| `AST-WH` | admission-webhook | Service (Go) | `admission-webhook` | `8443/tcp`, `9090/tcp` | HTTPS TLS 1.3 (server-auth only) `8443`; HTTP metrics (unauth.) `9090` | In-Boundary |
| `AST-PM` | policy-manager | Service (Go) | `policy-manager` | `8080/tcp`, `9091/tcp` | HTTPS TLS 1.3 REST `/api/v1` `8080` (server-auth; OIDC authN config-gated, default off); HTTP metrics (unauth.) `9091` | In-Boundary |
| `AST-DB` | dashboard BFF | Service (Go) | `dashboard` | `8090/tcp`, `9092/tcp` | HTTP (no user authn; write-gated by `ALLOW_WRITES`) `8090`; HTTP metrics (unauth.) `9092` | In-Boundary |
| `AST-SPA` | Svelte dashboard SPA | Web app (static assets) | embedded in `AST-DB` | served by `AST-DB:8090` | HTTP via `AST-DB` | In-Boundary |
| `AST-OPA` | OPA/Rego policy evaluator | Embedded library (Go) | n/a | n/a | n/a | In-Boundary |

- `AST-WH` serves `/validate` and `/mutate` AdmissionReview calls and exposes Prometheus metrics
  on `9090`. Embeds `AST-OPA`. Source: `cmd/admission-webhook/main.go`.
- `AST-PM` provides Policy/PolicyException lifecycle and decision intake over `/api/v1`,
  reconciles the CRDs against the kube-apiserver with leader election, and exposes metrics on
  `9091`. Embeds `AST-OPA`. Source: `cmd/policy-manager/main.go`.
- `AST-DB` is the backend-for-frontend that serves `AST-SPA` plus `/api` and reverse-proxies
  `/api/v1` to `AST-PM:8080`; it is read-only unless `ALLOW_WRITES=true`. Source:
  `cmd/dashboard/main.go`.
- `AST-SPA` is the Svelte single-page application compiled into the dashboard image. Source:
  `web/`, `cmd/dashboard/web_embed.go`.
- `AST-OPA` is the OPA/Rego evaluation engine compiled into `AST-WH` and `AST-PM` — not a
  separately deployed pod. Source: `internal/policy/engine.go`.

## In-boundary data objects (CRDs)

| Asset ID | Name | Kind | API resource | Version | Boundary |
|---|---|---|---|---|---|
| `AST-CRD-POL` | Policy CRD | `Policy` (Namespaced) | `policies.policies.kube-policies.io` | `v1` | In-Boundary |
| `AST-CRD-EXC` | PolicyException CRD | `PolicyException` (Namespaced) | `policyexceptions.policies.kube-policies.io` | `v1` | In-Boundary |

- Both CRDs are namespaced and stored by the kube-apiserver. Sources:
  `deployments/kubernetes/crds/policies.yaml`,
  `deployments/kubernetes/crds/policyexceptions.yaml`.

## In-boundary deployment artifact

| Asset ID | Name | Type | Version | Boundary |
|---|---|---|---|---|
| `AST-CHART` | Helm chart (RBAC/Services/Config) | Deployment artifact | `1.0.0` | In-Boundary |

- `AST-CHART` is the `kube-policies` Helm chart (`appVersion 1.0.0`) that installs all
  in-boundary workloads, RBAC, Services, ConfigMap, and TLS material into the
  `kube-policies-system` namespace. Source: `charts/kube-policies/`.

## External dependencies (`ZONE-EXT`)

| Asset ID | Name | Type | Version | Protocols | Boundary | Interconnection |
|---|---|---|---|---|---|---|
| `AST-EXT-APISERVER` | kube-apiserver | External (platform) | operator-supplied | HTTPS/TLS | External | `ICX-01`, `ICX-06` |
| `AST-EXT-PROMETHEUS` | Prometheus | External (monitoring) | operator-supplied | HTTP scrape (unauth.; TLS+authn target P3) | External | `ICX-03` |

- **kube-apiserver** calls `AST-WH:8443` for AdmissionReview (`ICX-01`), stores the CRDs, and is
  reconciled by `AST-PM` (`ICX-06`). It is provided and operated by the customer/CSP and is
  outside the authorization boundary.
- **Prometheus** scrapes the `:9090/:9091/:9092` metrics endpoints (`ICX-03`). The chart can
  optionally bundle a Prometheus subchart, but the scraping platform is treated as external.

## Cross-references

- [System facts sheet](system-facts.md) — authoritative source for asset IDs, ports, trust
  zones, and interconnections.
- [Authorization boundary diagram](diagrams/authorization-boundary.md) — visual placement of
  these `AST-*` assets across `ZONE-SYS`/`ZONE-EXT`.
- [System Security Plan](ssp/SSP.md) — consumes this inventory for the system-description
  section.
- [Control matrix](control-matrix.csv) — control implementation status spine (e.g., CM-8 system
  component inventory).
- [POA&M](poam.csv) — open weaknesses (unauthenticated planes, no FIPS module, image pinning,
  etc.) remediated across phases P1–P12.
