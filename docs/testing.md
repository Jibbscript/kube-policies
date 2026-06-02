---
title: "Test Strategy and Governance — Kube-Policies (KP)"
control_family: "SA — System and Services Acquisition"
controls: "SA-11, SA-11(1), SA-11(8), SA-15, SI-10, CA-8"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-02"
next_review: "2027-06-02"
---

# Test Strategy and Governance — Kube-Policies (KP)

This document describes the **test strategy and governance** for the Kube-Policies
system (KP): what is tested, how coverage is measured and ratcheted, who owns each
tier, and how every tier maps to a NIST SP 800-53 Rev 5 control. It is the
**strategy/governance layer**; the companion **[`TESTING.md`](../TESTING.md)** at
the repository root is the **operational how-to** covering cluster setup, environment
variables, Makefile targets, and troubleshooting steps.

Kube-Policies is a **Proof-of-Concept being driven to assessment readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. Named roles are not yet
staffed. Per-control status is tracked in the [control matrix](compliance/control-matrix.csv)
and open weaknesses in the [POA&M](compliance/POAM.md).

**Annual review.** This document is reviewed and updated at least **annually**. The
last review was **2026-06-02**; the **next review is 2027-06-02**. It is also
reviewed after any material change to the CI pipeline, coverage floor ratchet, or
fuzz-time budget. Reviews are recorded by updating the `last_reviewed`/`next_review`
front-matter and the version.

---

## 1 Test pyramid

KP employs six testing tiers arranged from fastest and most targeted (unit) to
broadest and most expensive (DAST). Each tier runs on a defined schedule and feeds
into the CI gate required for merge.

```
                    ┌──────────────┐
                    │     DAST     │  nightly (ZAP baseline + TLS)
                    ├──────────────┤
                    │   Mutation   │  weekly (gremlins)
                   ─┤              ├─
                  / │    Fuzz      │  40 s/target (PR smoke) + 10 m/target (nightly)
                 /  ├──────────────┤
                /   │     E2E      │  Kind + k3s (every PR/push after build)
               /    ├──────────────┤
              /     │ Integration  │  envtest (every PR/push)
             /      ├──────────────┤
            /       │    Unit      │  every PR/push  ← coverage floor gate
           ──────────────────────────
              Fast ◄──────────────► Broad
```

| Tier | Framework | Owner | NIST controls |
|---|---|---|---|
| Unit | `go test -race` | Maintainer | SA-11, SA-11(1) |
| Integration (envtest) | controller-runtime envtest | Maintainer | SA-11, SA-11(1) |
| E2E (Kind/k3s) | Ginkgo + Gomega; kind/k3s cluster scripts | Maintainer / Operator | SA-11, SA-15 |
| Fuzz | Go native fuzzing (`go test -fuzz`) | Maintainer | SA-11(8), SI-10 |
| DAST | OWASP ZAP; TLS checks | ISSO / Maintainer | CA-8, SA-11, RA-5(5) |
| Mutation | gremlins | Maintainer | SA-11, SA-15 |

---

## 2 Unit tests (SA-11, SA-11(1))

**What**: individual Go functions, handlers, and packages in isolation. Covers
admission-controller logic, policy-engine evaluation, configuration management,
audit logging, and metrics collection.

**Location**: `*_test.go` files co-located with source under `cmd/`, `internal/`,
and `pkg/`. Table-driven test patterns are preferred.

**Key fuzz-adjacent targets**: `FuzzAdmissionRequest` in `internal/admission/` and
`FuzzEngineEvaluate` in `internal/policy/` are also invoked under the fuzz tier
(§5); their seed corpora serve as regression inputs to the ordinary unit test
suite via `-run`.

**Makefile target**: `make test-unit` (equivalent: `go test -race -coverprofile=coverage.out ./cmd/... ./internal/... ./pkg/...`)

**CI job**: `unit-tests` in `.github/workflows/ci.yml` — runs on every PR/push;
required by the `ci-gate` aggregator.

**Coverage measurement**: `go tool cover -func` over the `-coverprofile` output.
Total statement coverage is compared against `MIN_COVERAGE` by
`scripts/test/cover-gate.sh`.

---

## 3 Integration tests — envtest (SA-11, SA-11(1))

**What**: component interactions and API contracts with a real Kubernetes API server
and etcd supplied by `controller-runtime/tools/setup-envtest` (no live cluster
needed). Tests cover admission-webhook request/response cycles, policy-manager API
operations, CRD validation and storage, and webhook-configuration management.

**Location**: `test/integration/`

**Framework**: Go testing with testify assertions; envtest binary set pinned to
Kubernetes v1.28.2.

**Coverage**: runs with `-coverpkg=./cmd/...,./internal/...,./pkg/...` so cross-package
coverage from integration-level calls is captured in `coverage-integration.out`.
A `make cover-merge` step (see `scripts/test/`) combines the unit and integration
profiles into a merged report for upload.

**Makefile targets**: `make test-integration`, `make cover-merge`

**CI job**: `integration-tests` in `.github/workflows/ci.yml` — runs after
`build-images`; required by `ci-gate`.

---

## 4 End-to-end tests — Kind / k3s (SA-11, SA-15)

**What**: complete workflows in a real Kubernetes cluster. Tests verify policy
enforcement on pod creation, policy exceptions and overrides, multi-rule policy
evaluation, and deployment/service policies.

**Location**: `test/e2e/` (Ginkgo + Gomega); `scripts/test/test-kind.sh`,
`scripts/test/test-k3s.sh`

**Cluster targets**:

| Target | Use case | CI job |
|---|---|---|
| Kind (v0.20.0) | Primary CI gate; local development | `e2e-kind` — required by `ci-gate` |
| k3s | Edge / resource-constrained validation | `e2e-k3s` — required by `ci-gate` |
| EKS | Cloud production environments | `scripts/test/test-eks.sh` — manual / on-demand |
| Vanilla kubeadm | On-premises | `scripts/test/test-vanilla.sh` — manual / on-demand |

**Makefile target**: `make test-e2e` (cluster must be pre-provisioned or use the
cluster-specific scripts).

**CI jobs**: `e2e-kind`, `e2e-k3s` in `.github/workflows/ci.yml` — both run after
`build-images`; both required by `ci-gate`.

---

## 5 Fuzz testing (SA-11(8), SI-10)

### 5.1 Targets

KP implements two Go native fuzz targets:

| Target function | Package | What it covers |
|---|---|---|
| `FuzzAdmissionRequest` | `./internal/admission/` | AdmissionReview parser — fail-closed / defined-verdict behavior under arbitrary input |
| `FuzzEngineEvaluate` | `./internal/policy/` | OPA/Rego evaluator — policy evaluation under arbitrary input without panic or undefined verdict |

Both targets use `testing.F` with Go's native fuzzer; no external fuzzing framework
is required.

### 5.2 Time budgets

| Mode | Duration per target | Trigger | Workflow |
|---|---|---|---|
| PR smoke | **40 seconds** | Every PR/push to `main`/`develop` | `fuzz-smoke` job in `.github/workflows/ci.yml` |
| Nightly extended | **10 minutes** | Scheduled daily 04:00 UTC; `workflow_dispatch` | `.github/workflows/fuzz-nightly.yml` |

The smoke budget (40 s) is sufficient to catch newly-introduced crashers on the
critical path without adding significant CI latency. The nightly budget (10 m) allows
meaningful coverage expansion and corpus accumulation; corpus artifacts are uploaded
after every nightly run regardless of outcome so seeds persist across runs.

### 5.3 Crasher handling

When the Go fuzzer writes a crasher, `go test` exits non-zero. The nightly workflow
also includes an explicit `check-for-crashers` step that inspects
`testdata/fuzz/<func>/` for `crash-*` files and emits a GitHub Actions error
annotation. Crasher artifacts are uploaded separately so the minimized input is
available for triage.

Crashers are treated as SEV2 (High) defects and tracked in the POA&M until
root-cause is fixed.

**Controls**: **SA-11(8)** (fuzz testing), **SI-10** (information input validation),
**SSDF PW.8** (test executable code to identify vulnerabilities).

---

## 6 DAST — OWASP ZAP (CA-8, SA-11, RA-5(5))

**What**: dynamic application security testing of the running stack. Runs OWASP ZAP
baseline scans against:
- Policy-manager REST API on `:8080`
- Dashboard BFF on `:3000` (if the service is present)
- TLS/cipher checks against the admission-webhook HTTPS endpoint on `:8443`

**Stack**: Kind cluster provisioned by reusing the `e2e-kind` pattern; services are
port-forwarded before ZAP runs.

**Severity gate**: failing at `High` or above by default (`FAIL_ON=High`); the
`workflow_dispatch` input allows `High`, `Medium`, or `Low`. SARIF results upload to
the GitHub Security tab under the `dast-api` and `dast-bff` categories.

**Trigger**: scheduled nightly (03:00 UTC); `pull_request` on changes to `web/**`
or `cmd/dashboard/**`; `workflow_dispatch`.

**Workflow**: `.github/workflows/dast.yml`

**Controls**: **CA-8** (penetration testing), **SA-11** (developer security
testing), **SC-8** (transmission confidentiality / TLS), **RA-5(5)** (privileged
access / vulnerability scanning).

---

## 7 Mutation testing (SA-11, SA-15)

**What**: evaluates test-suite quality by injecting source-level mutations (changed
operators, deleted returns, flipped conditions) into `internal/admission/...` and
`internal/policy/...` and measuring how many are "killed" (detected) by existing
tests.

**Tool**: `gremlins unleash` (v0.5.0, installed via `go install`).

**Informational minimum score**: **50%**. Gating via `--threshold` is intentionally
disabled on first adoption to establish a baseline. Once a stable baseline score has
been measured (SDL-WU-30 ratchet), `--threshold ${MIN_MUTATION_SCORE}` will be added
to the `gremlins` invocation and the `|| true` suffix removed. The weekly report
artifact (`mutation-report.json`) provides the baseline.

**Trigger**: weekly (Monday 05:00 UTC); `workflow_dispatch`.

**Workflow**: `.github/workflows/mutation.yml`

**Controls**: **SA-11** (developer security testing), **SA-15** (development process
standards and tools).

---

## 8 Coverage floor and ratchet schedule

### 8.1 Current floor

The **current enforced coverage floor is 60%**, set conservatively below the
measured unit-test total of **68.6%** (`go tool cover -func` over
`./cmd/... ./internal/... ./pkg/...` after the P11 tests landed). The floor
protects against regression while leaving headroom; the ratchet (§8.2) closes
the gap to the long-term 80% gate.

Two mechanisms enforce this floor:

| Mechanism | Location | Value | Behavior |
|---|---|---|---|
| `scripts/test/cover-gate.sh` | `MIN_COVERAGE=60` (default) | 60 | Fails `unit-tests` CI job if `go tool cover -func` total is below threshold |
| `codecov.yml` | `coverage.status.project.default.target: "60%"` | 60% | Codecov project status check (informational=true during ratchet) |

The Codecov **patch** check requires **80%** on all changed lines in a PR
(`informational: false`); this is already enforced and is not subject to the
ratchet.

### 8.2 Ratchet schedule

The floor ratchets upward quarterly. To advance a quarter: update `MIN_COVERAGE` in
`scripts/test/cover-gate.sh` (the `MIN_COVERAGE` environment variable passed by the
`unit-tests` CI job), update `coverage.status.project.default.target` in
`codecov.yml`, and flip `informational: false` once the gate is stable at the
new threshold.

| Quarter | Floor target | Gate state |
|---|---|---|
| Q1 2026 (baseline) | **60%** | Enforced (`informational: true` in Codecov; hard fail in cover-gate.sh) |
| Q2 2026 | **70%** | Enforce — update MIN_COVERAGE + codecov.yml |
| Q3 2026 | **80%** | Enforce; flip Codecov `informational: false` |

The ratchet values and schedule are co-documented in `scripts/test/cover-gate.sh`
(comment block at the top of the script). Both must be updated together.

### 8.3 Makefile targets

| Target | Description |
|---|---|
| `make test-unit` | Run unit tests with `-race -coverprofile=coverage.out` |
| `make test-integration` | Run integration tests with `-coverpkg` cross-package coverage |
| `make test-e2e` | Run E2E tests against a pre-provisioned cluster |
| `make cover-gate` | Run `scripts/test/cover-gate.sh coverage.out` locally |
| `make cover-merge` | Merge unit + integration coverage profiles |

---

## 9 Control mapping summary

| Test tier | Primary controls | Secondary / cross-references |
|---|---|---|
| Unit | SA-11 (developer testing), SA-11(1) (code analysis) | SSDF PW.8 |
| Integration (envtest) | SA-11, SA-11(1) | SSDF PW.8 |
| E2E (Kind/k3s) | SA-11, SA-15 (development standards) | SSDF PW.8 |
| Fuzz | SA-11(8) (fuzz testing), SI-10 (input validation) | SSDF PW.8 |
| DAST (ZAP) | CA-8 (penetration testing), SA-11, RA-5(5) | SC-8, SSDF RV.2 |
| Mutation | SA-11, SA-15 | SSDF PW.8 |
| Monthly vuln scan (govulncheck + Trivy) | RA-5, RA-5(2), RA-5(5), CA-7 | SI-2, SSDF RV.1 |
| POA&M aging | CA-5, PM-4, SI-2, SI-4 | RA-5 |

---

## 10 References

- Operational testing how-to: [`TESTING.md`](../TESTING.md)
- Secure SDLC (SDL phases, gate details): [docs/security/secure-sdlc.md](security/secure-sdlc.md)
- Coverage gate script: [`scripts/test/cover-gate.sh`](../scripts/test/cover-gate.sh)
- Codecov configuration: [`codecov.yml`](../codecov.yml)
- CI pipeline: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
- Nightly fuzz: [`.github/workflows/fuzz-nightly.yml`](../.github/workflows/fuzz-nightly.yml)
- DAST workflow: [`.github/workflows/dast.yml`](../.github/workflows/dast.yml)
- Mutation workflow: [`.github/workflows/mutation.yml`](../.github/workflows/mutation.yml)
- Vulnerability management: [`.github/workflows/monthly-vuln-scan.yml`](../.github/workflows/monthly-vuln-scan.yml)
- POA&M: [docs/compliance/POAM.md](compliance/POAM.md)
- Control matrix: [docs/compliance/control-matrix.csv](compliance/control-matrix.csv)
- NIST SP 800-53 Rev 5 (SA-11, SA-11(1), SA-11(8), SA-15, SI-10, CA-8, RA-5)
- NIST SP 800-218 SSDF (PW.8, RV.1, RV.2)
