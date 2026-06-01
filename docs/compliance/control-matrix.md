---
title: "FedRAMP-Moderate Control Matrix (NIST SP 800-53 Rev 5)"
control_family: "All (AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PS, RA, SA, SC, SI, SR, PM)"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign before assessment)"
approver: "Authorizing Official (TBD — assign before assessment)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# FedRAMP-Moderate Control Matrix — Kube-Policies (KP)

This document is the **human view** of the control matrix. The **machine-readable
spine** is [`control-matrix.csv`](control-matrix.csv) — that file, not this one, is
the authoritative per-control record consumed by tooling and the SSP. Edit the CSV
via its generator (see [How to maintain](#how-to-maintain)); this Markdown is a
rendered companion.

- **System:** Kube-Policies (Kubernetes admission-control & policy-management), abbrev **KP**
- **Categorization:** FIPS-199 **Moderate** (see [categorization/FIPS-199.md](categorization/FIPS-199.md))
- **Standard / baseline:** NIST SP 800-53 **Rev 5**, **FedRAMP Moderate** baseline
- **Authoritative system facts:** [system-facts.md](system-facts.md) (asset IDs `AST-*`, ports, trust zones `ZONE-EXT`/`ZONE-SYS`, interconnections `ICX-01..06`)
- **Cross-references:** [System Security Plan (SSP)](ssp/SSP.md) · [Plan of Action & Milestones (POA&M)](POAM.md) / [`poam.csv`](poam.csv) · [Component Inventory](inventory.csv)

> **Annual review.** This matrix and its source CSV are reviewed at least annually
> (next review **2027-05-29**) and whenever a remediation phase (P0–P12) closes,
> the baseline changes, or the system boundary changes. Reviewers reconcile every
> row against the as-built repository and the official FedRAMP Rev5 Moderate OSCAL
> profile (see [Maintenance & OSCAL reconciliation](#maintenance--oscal-reconciliation)).

## How to read a row

Each CSV row is one Moderate control or enhancement. Columns:

| Column | Meaning |
|---|---|
| `control_id` | NIST 800-53 Rev 5 identifier, e.g. `AC-2`, `AU-9(4)`, `SC-7(5)`. |
| `title` | Control / enhancement title. |
| `family` | Two-letter family code (`AC`…`SR`, plus `PM`). |
| `baseline` | Always `Moderate` for this system. |
| `status` | `Implemented` \| `Partial` \| `Planned` \| `Inherited` \| `Customer` \| `Not-Applicable`. |
| `responsible_party` | `System` \| `CSP` \| `Customer` \| `Shared`. |
| `implementing_artifact` | A repo path (e.g. `cmd/admission-webhook/main.go`) or a phase pointer (`see P4`). |
| `remediating_phase` | `P0`–`P12` from [PRODUCTION-READINESS-FEDRAMP-CIS.md](../../.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md). |
| `poam_id` | Linked open weakness in [`poam.csv`](poam.csv) (e.g. `POAM-001`), or blank. |
| `notes` | Assessor-facing rationale; cites the bright spot or the gap. |

### Status legend

- **Implemented** — control is fully satisfied today by a shipped artifact (no open work).
- **Partial** — a genuine *bright spot* exists in the code/chart but the control is not fully met; remediation is scoped to a phase.
- **Planned** — not yet implemented; remediation is scoped to a phase (most rows, honestly, are here — this is a PoC being driven to readiness).
- **Inherited** — satisfied by the hosting CSP / underlying infrastructure (e.g. the entire **PE** family, environmental **MP**, alternate sites in **CP**). Confirmed via the CSP ATO / Customer Responsibility Matrix during P12.
- **Customer** — the consuming agency/operator is responsible (used for `responsible_party`).
- **Not-Applicable** — no in-boundary component exercises the control (e.g. `AC-18` wireless, `SC-15` collaborative computing, `SI-8` spam).

> **Honesty note.** This is a proof-of-concept on the path to ATO. Of 300 in-scope
> rows, only **3 are Implemented** (`RA-2` categorization, `PL-10` baseline
> selection, `AC-1` access-control policy) and **47 are Partial**. The Partial rows
> are real, code-backed bright spots — they are not aspirational; several IAM rows
> (`AC-2/3/5/17`, `IA-2`) are **Partial because their enforcement is config-gated**
> on `security.authentication.enabled` (chart default off = management plane
> unauthenticated, a dev-only tracked gap), not because they are fully met.
> Everything else is **Planned** or **Inherited** and is traceable to a remediation
> phase and, where it is a known open weakness, a POA&M item.

## Coverage summary

300 in-scope rows across all 18 control families plus **PM** program controls.

| Family | Controls | Implemented | Partial | Planned | Inherited | N/A |
|---|---|---|---|---|---|---|
| AC — Access Control | 38 | 1 | 6 | 24 | 4 | 3 |
| AT — Awareness and Training | 6 | 0 | 0 | 6 | 0 | 0 |
| AU — Audit and Accountability | 19 | 0 | 4 | 15 | 0 | 0 |
| CA — Assessment, Authorization, and Monitoring | 13 | 0 | 1 | 12 | 0 | 0 |
| CM — Configuration Management | 22 | 0 | 4 | 18 | 0 | 0 |
| CP — Contingency Planning | 22 | 0 | 2 | 10 | 10 | 0 |
| IA — Identification and Authentication | 22 | 0 | 3 | 13 | 6 | 0 |
| IR — Incident Response | 12 | 0 | 0 | 12 | 0 | 0 |
| MA — Maintenance | 9 | 0 | 0 | 4 | 5 | 0 |
| MP — Media Protection | 7 | 0 | 0 | 2 | 5 | 0 |
| PE — Physical and Environmental Protection | 19 | 0 | 0 | 0 | 19 | 0 |
| PL — Planning | 7 | 1 | 3 | 3 | 0 | 0 |
| PS — Personnel Security | 9 | 0 | 0 | 8 | 1 | 0 |
| RA — Risk Assessment | 8 | 1 | 3 | 4 | 0 | 0 |
| SA — System and Services Acquisition | 19 | 0 | 8 | 11 | 0 | 0 |
| SC — System and Communications Protection | 27 | 0 | 5 | 18 | 3 | 1 |
| SI — System and Information Integrity | 17 | 0 | 5 | 11 | 0 | 1 |
| SR — Supply Chain Risk Management | 14 | 0 | 1 | 13 | 0 | 0 |
| PM — Program Management | 10 | 0 | 2 | 8 | 0 | 0 |
| **Total** | **300** | **3** | **47** | **192** | **53** | **5** |

> The per-family **control selection** above is a working approximation of the
> FedRAMP Moderate baseline and **must be reconciled against the official OSCAL
> profile** before assessment (see below). Counts are derived from the CSV.

## Bright spots (the Partial / Implemented rows)

These are the controls where the repository already does real work. They are
deliberately marked **Partial** (or **Implemented**) and cite the exact artifact:

- **SC-7 / SC-7(3)(4)(5)(7) — Boundary protection / network segmentation
  (Implemented (Helm) — requires enforcing CNI).** The chart and the static base
  manifest render a **default-deny** baseline plus a least-privilege allow-list
  (`charts/kube-policies/templates/networkpolicy-*.yaml`,
  `deployments/kubernetes/base/networkpolicy.yaml`); every allowed flow is mapped to
  its template in [network-architecture.md](network-architecture.md) (also the CA-3
  scoped-flow record). **Enforcement requires a NetworkPolicy-enforcing CNI**
  (Calico/Cilium/Antrea) — inert on kindnet — and the live e2e proof is not yet run,
  so it is **not** "enforced by default" (residual **POAM-007**).
- **SC-5 — Denial-of-service protection (Partial).** Per-replica rate limiting, body
  cap (413), concurrency + SSE caps (429), and the
  `kube_policies_http_rate_limited_total` metric ship on by default
  (`internal/middleware/ratelimit.go`); ResourceQuota/LimitRange ship **off** by
  default (residual **POAM-027**).
- **SC-8 / SC-8(1) — Transmission protection (Partial).** The admission webhook
  serves **TLS 1.3** with a fixed modern cipher-suite list
  (`cmd/admission-webhook/main.go`); this protects `ICX-01`
  (kube-apiserver → `AST-WH:8443`). **P2/P3** added TLS 1.3 on the policy-manager API
  (`internal/config/tls.go`) and a **verified-HTTPS** webhook→policy-manager decisions
  channel (RootCAs, no `InsecureSkipVerify`, audience-bound token —
  `internal/admission/decision_publisher.go`). Dashboard in-pod TLS and metrics-plane
  authN remain **config-gated and off by default** (residual **POAM-004**).
- **AC-3 / AC-5 / AC-6 — Access enforcement, separation of duties, least privilege (Partial).**
  Each plane runs under its **own** ServiceAccount bound to its **own** (Cluster)Role
  (`charts/kube-policies/templates/rbac.yaml`, `…/dashboard-rbac.yaml`): webhook and
  policy-manager get only CRD `get/list/watch` + `/status` patch, the TokenReview
  `create` grant is on the policy-manager only, and the dashboard Role is read-only on
  two named Services. The decision plane is authenticated unconditionally via
  TokenReview (Inc7). The **management-plane** OIDC + deny-by-default RBAC
  (`internal/policymanager/authz.go`) is **config-gated** on
  `security.authentication.enabled` (chart default off = unauthenticated, dev-gap),
  which is why these stay **Partial**. See [iam-control-narrative.md](iam-control-narrative.md).
- **AU-2 / AU-3 / AU-12 — Audit (Partial).** The webhook logs **every** allow/deny
  decision with who/what/when via `internal/audit/logger.go`. Missing record fields
  (source IP, user-agent, request-URI), tamper protection, durability, and
  management-plane coverage are added in **P7** (**POAM-002**).
- **CM-2 / CM-6 / CM-7 — Baseline & least functionality (Partial).** Config
  validation pins TLS 1.3, validates `failure_mode` and defaults **fail-closed**,
  and ships **distroless** images (`internal/config/config.go`,
  `charts/kube-policies/values.yaml`); the full CIS-restricted baseline is **P5**.
- **CP-10 / SC-6 — Recovery & availability (Partial).** Leader election +
  multi-replica webhook (`cmd/admission-webhook/main.go`); PDBs, anti-affinity, HA
  policy-manager, and RTO/RPO land in **P8**.
- **SI-4 — System monitoring (Partial).** A real Prometheus collector exists
  (`internal/metrics/collector.go`); SIEM-grade detection/alerting is **P9**.
- **SR-3 / SA-10 / SA-11 — Supply chain & dev testing (Partial).** SBOM generation
  and unit tests exist (`.github/workflows/release.yml`, `ci.yml`) but are
  unverified/non-gating; signing, provenance, and gated scans land in **P6/P11**
  (**POAM-006**, **POAM-008**).
- **IA-2 / IA-3 / IA-5 — Identification & authentication (Partial).** OIDC ID-token
  bearer authN (`internal/policymanager/auth_middleware.go`, config-gated),
  audience+subject-bound projected SA tokens via TokenReview
  (`internal/policymanager/tokenreview.go`, `tokenreview` mode is the chart default),
  and managed bearer/cert authenticator lifecycles (`internal/auth/token.go`,
  cert-manager + `internal/tlsreload`). MFA/PIV and the remaining chart-side CSPRNG
  token generation are tracked. See [iam-control-narrative.md](iam-control-narrative.md).
- **RA-2 (Implemented), PL-10 (Implemented), AC-1 (Implemented).** Categorization,
  baseline selection, and the AC-1 access-control policy + procedures
  ([policies/AC-policy.md](policies/AC-policy.md),
  [procedures/AC-procedures.md](procedures/AC-procedures.md)) are complete; baseline
  selection still carries an OSCAL-reconciliation obligation (**POAM-009**).

## Inherited and Not-Applicable rationale

- **Inherited (53 rows).** The entire **PE** family, environmental **MP** (media
  storage/marking/transport/sanitization), alternate-site/telecom **CP** controls
  (`CP-6/7/8`), DNS resolution (`SC-20/21/22`), and IdP-provided authenticator
  mechanics (`IA-5(1)`, `IA-6`, `IA-12*`, `AC-7`) are satisfied by the hosting CSP
  or federated identity provider. Each must be confirmed against the CSP ATO /
  Customer Responsibility Matrix during **P12**.
- **Not-Applicable (5 rows).** `AC-18`/`AC-18(1)` (no wireless), `AC-22` (no public
  content service), `SC-15` (no collaborative computing), `SI-8` (no email/messaging).
  N/A determinations are part of baseline tailoring (`PL-11`) and must survive OSCAL
  reconciliation.

## Maintenance & OSCAL reconciliation

> **MANDATORY before assessment.** The control selection in this matrix (which
> controls and enhancements are in the Moderate baseline, and which are tailored
> out as N/A) is a **working approximation**. It **must be reconciled against the
> authoritative FedRAMP Rev 5 Moderate OSCAL profile**
> (the FedRAMP baseline resolved profile / `FedRAMP_rev5_MODERATE-baseline_profile`).
> Any control present in the official OSCAL baseline but missing here must be added;
> any control here that the official baseline does not require must be re-tailored
> with documented justification.

This reconciliation is itself tracked as a POA&M item: **POAM-009** in
[`poam.csv`](poam.csv) (control `PL-10`/`PL-11`, baseline selection & tailoring).
Do not treat the matrix as assessment-ready until POAM-009 is closed.

### How to maintain

The CSV is **generated**, never hand-edited row-by-row, so that validation and
counts stay consistent:

1. Edit the generator: [`_gen_control_matrix.py`](_gen_control_matrix.py). Each
   control is one `add(...)` call. Use the `AST-*` IDs, ports, zones, and `ICX-*`
   IDs from [system-facts.md](system-facts.md) **verbatim** — never invent new IDs.
2. Regenerate and validate from the repo root:
   ```sh
   python3 docs/compliance/_gen_control_matrix.py
   ```
   The script asserts: one row per control (no duplicates), `status` in the allowed
   set, `responsible_party` in `{System,CSP,Customer,Shared}`, and **no blank
   `status` or `responsible_party` cells**. It prints per-status and per-family
   counts.
3. Update the **Coverage summary** table and **Bright spots** list in this Markdown
   to match the regenerated counts.
4. When a phase (P0–P12) closes, flip the affected rows from `Planned`/`Partial` to
   `Partial`/`Implemented`, point `implementing_artifact` at the merged repo path,
   and close or update the linked `poam_id` in [`poam.csv`](poam.csv).
5. Keep the matrix, [SSP](ssp/SSP.md), [POA&M](POAM.md), and
   [inventory](inventory.csv) mutually consistent — the matrix is the spine; the SSP
   narratives and POA&M weaknesses reference `control_id` values from this file.

### Conventions (must match across all compliance artifacts)

- CSV header is **exactly**:
  `control_id,title,family,baseline,status,responsible_party,implementing_artifact,remediating_phase,poam_id,notes`
- `status` ∈ `{Implemented, Partial, Planned, Inherited, Customer, Not-Applicable}`;
  `responsible_party` ∈ `{System, CSP, Customer, Shared}`.
- `remediating_phase` ∈ `{P0…P12}`; phases are defined in
  [PRODUCTION-READINESS-FEDRAMP-CIS.md](../../.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md).
- `poam_id` values match `poam_id` in [`poam.csv`](poam.csv) (`POAM-NNN`).
- Named roles are not yet staffed — use titles (System Owner, ISSO, AO, Independent
  Assessor) with "TBD — assign before assessment".

## Related artifacts

- [System Security Plan (SSP)](ssp/SSP.md) — control narratives reference `control_id` values here.
- [Plan of Action & Milestones (POA&M)](POAM.md) · [`poam.csv`](poam.csv) — open weaknesses (`POAM-001`…`POAM-010`, incl. **POAM-009** OSCAL reconciliation).
- [Component Inventory](inventory.csv) — `AST-*` assets cited in `implementing_artifact`.
- [System Facts Sheet](system-facts.md) — canonical IDs, ports, zones, interconnections.
- [FIPS-199 Categorization](categorization/FIPS-199.md) — Moderate categorization basis.
- [Production-Readiness Plan (P0–P12)](../../.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md) — remediation phases.
