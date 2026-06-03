---
title: "Data Flow Diagram"
control_family: "CA / SC — Boundary & Data Flow"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Data Flow — Kube-Policies (KP)

This diagram shows the runtime data flows for the Kube-Policies (KP) system
(**FIPS-199 Moderate**; NIST SP 800-53 Rev 5 / FedRAMP Moderate baseline). It is the
companion to the [Authorization Boundary Diagram](authorization-boundary.md) and uses the
canonical asset IDs, ports, and interconnection IDs (`ICX-01..06`) from the
[System Facts Sheet](../system-facts.md). Each interconnection is enumerated with sensitivity
and protection in the [Interconnection Register](../interconnections.md). Referenced from the
[SSP](../ssp/SSP.md).

**Annual review.** This artifact is reviewed at least annually (next review **2027-05-29**)
and whenever a data flow or interconnection materially changes.

## Sequence — admission, decision publish, reconcile, dashboard, metrics

```mermaid
sequenceDiagram
    autonumber
    participant API as kube-apiserver (ZONE-EXT)
    participant WH as AST-WH admission-webhook (ZONE-SYS)
    participant OPA as AST-OPA evaluator (embedded)
    participant PM as AST-PM policy-manager (ZONE-SYS)
    participant DB as AST-DB dashboard (ZONE-SYS)
    participant PROM as Prometheus (ZONE-EXT)

    Note over API,WH: ICX-01 · AdmissionReview · TLS 1.3 (server-auth only)
    API->>WH: POST /validate or /mutate (AdmissionReview) @ :8443 [TLS 1.3]
    WH->>OPA: Evaluate object spec against compiled Rego
    OPA-->>WH: allow / deny (+ mutations)
    WH-->>API: AdmissionReview response (allow/deny) @ :8443 [TLS 1.3]

    Note over WH,PM: ICX-02 · decision publish · HTTP + static bearer token
    WH->>PM: POST /api/v1/decisions/internal (decision records + bearer) @ :8080

    Note over PM,API: ICX-06 · CRD reconcile + Lease · in-cluster TLS (SA token)
    PM->>API: Watch/Get/Update Policy & PolicyException CRDs, Lease @ apiserver
    API-->>PM: CRD events / reconcile results

    Note over DB,PM: ICX-04 · dashboard feed · HTTP
    DB->>PM: GET /api/v1 (policy data + decisions stream) @ :8080
    PM-->>DB: Policy data / decision feed

    Note over PROM,DB: ICX-03 · metrics scrape · HTTP, unauthenticated
    PROM->>WH: GET /metrics @ :9090
    PROM->>PM: GET /metrics @ :9091
    PROM->>DB: GET /metrics @ :9092
```

## Flow overview (boundary crossings highlighted)

```mermaid
flowchart LR
    API["kube-apiserver<br/>ZONE-EXT"]
    PROM["Prometheus<br/>ZONE-EXT"]
    USERS["Operators / Users<br/>ZONE-EXT"]

    subgraph ZSYS["Authorization Boundary (ZONE-SYS / kube-policies-system)"]
        WH["AST-WH<br/>:8443 / :9090"]
        OPA["AST-OPA<br/>(embedded)"]
        PM["AST-PM<br/>:8080 / :9091"]
        DB["AST-DB + AST-SPA<br/>:8090 / :9092"]
    end

    API ==>|"ICX-01 AdmissionReview · TLS 1.3"| WH
    WH --- OPA
    WH -->|"ICX-02 decision publish · HTTP + bearer · :8080"| PM
    PM ==>|"ICX-06 CRD reconcile + Lease · in-cluster TLS"| API
    DB -->|"ICX-04 policy/decision feed · HTTP · :8080"| PM
    USERS ==>|"ICX-05 dashboard UI/API · HTTP"| DB
    PROM ==>|"ICX-03 metrics · HTTP :9090/:9091/:9092"| WH
    PROM ==>|"ICX-03 metrics · HTTP"| PM
    PROM ==>|"ICX-03 metrics · HTTP"| DB

    classDef inb fill:#e6f4ea,stroke:#1e7e34,color:#0b3d1a;
    classDef ext fill:#fdecea,stroke:#c0392b,color:#5a1a13;
    class WH,OPA,PM,DB inb;
    class API,PROM,USERS ext;
```

## Annotations

- **`ICX-01` (apiserver → `AST-WH:8443`)** — AdmissionReview request/response. Transport is
  **TLS 1.3** (server-auth only today; apiserver mTLS is a phase **P3** target). This is the
  only flow with transport encryption in the current build.
- **`AST-WH` → `AST-OPA`** — in-process Rego evaluation (embedded library; no network hop).
- **`ICX-02` (`AST-WH` → `AST-PM:8080`)** — admission decision records published to
  `/api/v1/decisions/internal` over **HTTP with a static bearer token**; TLS + audience-bound
  token is a phase **P3/P4** target.
- **`ICX-06` (`AST-PM` ↔ kube-apiserver)** — `Policy`/`PolicyException` reconcile plus leader-
  election Lease over the in-cluster kubeconfig/SA token (TLS to apiserver); least-privilege SA
  is a phase **P3** target.
- **`ICX-04` (`AST-DB` → `AST-PM:8080`)** — dashboard pulls policy data and the decision feed
  over **HTTP**; TLS is a phase **P4** target.
- **`ICX-03` (Prometheus → `:9090/:9091/:9092`)** — operational metrics scraped over
  **unauthenticated HTTP**; TLS + authn is a phase **P3** target.
- **`ICX-05` (Operators/Users → `AST-DB:8090`)** — dashboard UI/API over **HTTP with no user
  authentication** (writes gated by `ALLOW_WRITES`); TLS + OIDC login is a phase **P3** target.

Current-vs-target transport posture and remediation phases are tracked in the
[Interconnection Register](../interconnections.md) and the [POA&M](../poam.csv).
