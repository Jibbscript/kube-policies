# Kube-Policies — FedRAMP-Moderate / CIS Remediation Roadmap

| | |
|---|---|
| **Status** | Living document (committed, in-repo) |
| **Scope** | NIST SP 800-53r5 FedRAMP-Moderate baseline + CIS Kubernetes Benchmark v1.8 + NIST SP 800-190 |
| **Owner** | System Owner / ISSO (role placeholders — see [POAM.md](../POAM.md)) |
| **Last reviewed** | 2026-06-02 |

> **Why this document exists.** This is the committed, self-contained summary of the
> phased remediation program that takes Kube-Policies from PoC/MVP to ATO-readiness.
> It is the authoritative in-repo reference for the phase model, control coverage,
> and the human-owned items that must land in the POA&M. The full atomic-work-unit
> breakdown (285 work units) was authored as a planning artifact; this roadmap
> reproduces its checkpoint-gating model and coverage so every compliance document
> can cite an in-tree source rather than an external planning file.

## Gating model

The program is an ordered set of **13 checkpoint-gated phases** containing **285 atomic
work units**. Each work unit is independently completable, verifiable, and traceable to
specific NIST/CIS controls. Phases are dependency-ordered; each has:

- an **entry gate** — preconditions that must hold before the phase starts; and
- an **exit gate** — an evidence-based checkpoint (passing tests/scans/renders + committed
  artifacts) that must pass before the phase is marked complete.

A phase is not "done" until its exit gate is demonstrably met in CI. Residual gaps that
cannot be closed within a phase are logged to [POAM.md](../POAM.md) with a severity,
owner, and milestone.

## Phases

| Phase | Title | WUs | Depends on | Control families |
|---|---|---|---|---|
| **P0** | Compliance Foundation: Categorization, Boundary, Control Matrix/SSP Skeleton, Threat Model, Secure Baseline | 16 | — | RA, PL, CA, CM, SC, SR, PM |
| **P1** | Build-Pipeline & Toolchain Integrity Baseline (CI trustworthiness prerequisite) | 15 | P0 | CM, SR, SA, SI, AC |
| **P2** | Cryptographic & FIPS Foundation | 23 | P1 | SC, IA, SI, CM |
| **P3** | Identity, Authentication, Authorization & RBAC Least-Privilege | 19 | P2 | AC, IA, SC, AU |
| **P4** | Network Segmentation & Communications Protection | 25 | P3 | SC, AC, CA, CM |
| **P5** | Workload/Container Hardening & Configuration Management | 19 | P4 | CM, SC, SI, AC, RA |
| **P6** | Supply-Chain Integrity, SBOM, Signing, Provenance & Verification | 20 | P5 | SR, SA, SI, CM, RA |
| **P7** | Audit & Accountability: Durability, Integrity, Retention, Forwarding | 18 | P6 | AU, SI, AC, CA |
| **P8** | Contingency, Availability, Resilience & Backup | 18 | P7 | CP, SC, CM |
| **P9** | Detection, Monitoring, Alerting, SIEM & Incident Response | 32 | P8 | IR, SI, AU, CA, CP |
| **P10** | Policy Library Completeness (what the product actually enforces) | 31 | P9 | CM, AC, SC, SR, CA |
| **P11** | Secure-SDLC Quality Gates, Test Coverage, SAST/DAST/Fuzz & Vulnerability Management | 41 | P10 | SA, RA, SI, CA, CM, SR, IA |
| **P12** | Assessment & ATO Readiness: SSP Finalization, POA&M, Independent Review + Pen Test, ConMon Go-Live | 8 | P11 | CA, PL, PM, SA, RA, AT, MA, PS, MP, PE |
| | **Total** | **285** | | |

## Control coverage matrix

| Family / CIS section | Status | Addressed by |
|---|---|---|
| AC (Access Control) | covered | P3, P4, P5, P6, P7, P9, P10, P11 |
| AT (Awareness and Training) | partial | P9, P12 |
| AU (Audit and Accountability) | covered | P3, P7, P9 |
| CA (Assessment, Authorization & Monitoring) | covered | P0, P4, P9, P11, P12 |
| CM (Configuration Management) | covered | P0, P1, P2, P5, P6, P10 |
| CP (Contingency Planning) | covered | P8, P9 |
| IA (Identification and Authentication) | covered | P2, P3, P11 |
| IR (Incident Response) | covered | P9, P12 |
| MA (Maintenance) | partial | P9, P12 |
| MP (Media Protection) | partial | P12 |
| PE (Physical and Environmental Protection) | inherited-from-CSP | P12 |
| PL (Planning) | covered | P0, P12 |
| PS (Personnel Security) | partial | P0, P12 |
| RA (Risk Assessment) | covered | P0, P1, P5, P6, P9, P11 |
| SA (System and Services Acquisition) | covered | P1, P6, P11, P12 |
| SC (System and Communications Protection) | covered | P2, P3, P4, P5, P8, P9 |
| SI (System and Information Integrity) | covered | P2, P6, P7, P9, P11 |
| SR (Supply Chain Risk Management) | covered | P1, P6, P10, P11 |
| CIS 1 (Control Plane / apiserver & etcd) | partial | P2, P7, P8 |
| CIS 2 (etcd configuration) | inherited-from-CSP | P2, P8 |
| CIS 3 (Control Plane audit policy) | covered | P2, P3, P7 |
| CIS 4 (Worker Nodes / kubelet TLS) | partial | P2, P5 |
| CIS 5 (Policies: RBAC, PSS, NetworkPolicy, Secrets) | covered | P3, P4, P5, P10 |

The authoritative, row-per-control source of truth is
[control-matrix.csv](../control-matrix.csv) (and its rendered companion
[control-matrix.md](../control-matrix.md)).

## Human-owned / out-of-band items (not codebase-resolvable)

These are required for ATO but cannot be closed by repository work units alone; a program
owner / 3PAO / AO must own them. They are tracked in [POAM.md](../POAM.md) so they are not
lost:

- **P12 assessment activities** — SSP finalization, independent code review and penetration
  test *execution*, the ATO authorization decision, and continuous-monitoring go-live. The
  pen-test *plan* and *ConMon plan* are authored in-repo; their *execution by an independent
  3PAO* and the *AO authorization decision* must be staffed.
- **AT (Awareness and Training)** — only the AT-1 policy exists; role-based training content,
  delivery, and records (AT-2/AT-3) are organizational.
- **MA (Maintenance)** — only MA-1; MA-2/MA-4/MA-5 operational/controlled/remote maintenance
  are operator/organizational responsibilities.
- **MP (Media Protection)** — only MP-1; MP-2..MP-7 are CSP-inherited or operator-owned.
- **PE (Physical and Environmental)** — fully inherited from the hosting CSP; must be claimed
  via the CSP's existing FedRAMP authorization.
- **PS (Personnel Security)** — only PS-1 + roles-RACI; PS-2/PS-3/PS-7 screening and
  position-risk are HR/program-owned.
- **FedRAMP Privacy** — a human must determine whether a PTA/PIA is required (audit records
  may embed PII; AUD redaction is in place).
- **CIS 1.1.x/1.2.x and 4.2.x** (control-plane file permissions, etcd encryption-at-rest,
  kubelet TLS) — on managed control planes (EKS/GKE/AKS) these are CSP-inherited; a human
  must reconcile inherited vs customer-responsibility in the [CRM](../CRM.md) per environment.
- **OIDC IdP selection, AAL decisions, and AC-2 account lifecycle** — depend on an external
  IdP out of repo scope; a human must select/operate the IdP and document AC-2 against it.

## Related artifacts

- [SSP.md](../ssp/SSP.md) — System Security Plan (control narratives + evidence)
- [control-matrix.csv](../control-matrix.csv) / [control-matrix.md](../control-matrix.md) — control traceability
- [CRM.md](../CRM.md) — Customer Responsibility Matrix
- [POAM.md](../POAM.md) — Plan of Action & Milestones
- [assessment/SAP.md](../assessment/SAP.md) — Security Assessment Plan
- `authorization-package/` — assembled readiness package (created in P12-WU-07)
