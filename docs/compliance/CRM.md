---
title: "Control Implementation Summary / Customer Responsibility Matrix (CRM)"
control_family: "PL, SA, CA (cross-cutting)"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-05-29"
next_review: "2027-05-29"
---

# Control Implementation Summary / Customer Responsibility Matrix (CRM)

This Control Implementation Summary (CIS) and Customer Responsibility Matrix (CRM)
allocates every NIST SP 800-53 Rev 5 control family in the FedRAMP **Moderate**
baseline (FIPS-199 categorization: **Moderate** — see
[FIPS-199 categorization](categorization/FIPS-199.md)) to a responsible party for
the Kube-Policies system (KP). It satisfies NIST PL-2, SA-9, and CA-3 and is the
authoritative responsibility allocation that the [control matrix](control-matrix.csv)
`responsible_party` column must agree with.

Kube-Policies ships as a Helm chart (`charts/kube-policies`, asset `AST-CHART`)
deployed into a single namespace (`kube-policies-system`) on a Kubernetes cluster
that the **customer (cluster operator)** owns and that runs on infrastructure
operated by a **hosting Cloud Service Provider (CSP)**. That three-party split —
**System** (this product), **Customer** (cluster operator), **CSP** (FedRAMP-authorized
infrastructure/IaaS-or-managed-Kubernetes provider) — drives every allocation below.

> **Honesty note.** Kube-Policies is a proof-of-concept being driven to FedRAMP
> readiness. Most System-Implemented controls are **Planned** or **Partial** and
> are remediated across phases **P1–P12** (see
> [`plans/remediation-roadmap.md`](plans/remediation-roadmap.md)).
> Only the bright spots called out in the [system facts](system-facts.md) (webhook
> TLS 1.3, fail-closed default, read-only dashboard default, distroless non-root
> dashboard pod, leader election) are claimed as implemented today.

## Annual review

This CRM is reviewed at least annually (next review **2027-05-29**) and whenever the
authorization boundary, the hosting CSP, the shipped Helm chart, or the
responsibility split materially changes, and re-approved by the Authorizing Official
(TBD — assign before assessment).

## Responsibility allocation key

| Allocation | Meaning | Who acts |
|---|---|---|
| **System-Implemented** | The Kube-Policies product (code, chart, CRDs, docs) implements the control inside the authorization boundary (`ZONE-SYS`). | System Owner / ISSO (TBD — assign) |
| **CSP-Inherited** | Wholly inherited from the hosting CSP's existing FedRAMP authorization (physical/environmental and base-infrastructure controls). | Hosting CSP (named in the customer's ATO package) |
| **Customer-Responsibility** | The adopting cluster operator must implement and operate the control outside the shipped chart (cluster/control-plane/node/RBAC/CNI configuration, organizational programs). | Customer (cluster operator) |
| **Shared** | Responsibility is split; the row documents the System part and the Customer/CSP part. | Multiple — see split column |

These four allocations map to the [control matrix](control-matrix.csv)
`responsible_party` column values **System**, **CSP**, **Customer**, and **Shared**
respectively, and to its `status` values as follows: System-Implemented →
`Implemented`/`Partial`/`Planned`; CSP-Inherited → `Inherited`; Customer-Responsibility
→ `Customer`; Shared → `Partial`/`Shared` with the split documented here. Where the
matrix records a control as `Not-Applicable`, this CRM mirrors that with no operator
action required.

> **PE inheritance basis.** All Physical and Environmental Protection (PE) controls
> are **CSP-Inherited** from the hosting CSP's FedRAMP-authorized facilities; the
> customer must cite the specific CSP authorization package (e.g., the IaaS/managed-Kubernetes
> provider's FedRAMP Moderate ATO) in their own SSP. Kube-Policies operates no
> physical infrastructure. See [PE family allocation](#pe--physical-and-environmental-protection).

## Allocation summary by family

| Family | Primary allocation | Notes |
|---|---|---|
| AC — Access Control | **Shared** | System: webhook/API/RBAC inside chart; Customer: cluster RBAC, OIDC IdP, node access |
| AT — Awareness and Training | **Customer-Responsibility** | Organizational training program; System provides only AT-1 policy |
| AU — Audit and Accountability | **Shared** | System: decision audit records; Customer: control-plane audit, SIEM, retention storage |
| CA — Assessment, Authorization & Monitoring | **Shared** | System: SSP/SAP/ConMon artifacts; Customer: ATO decision, 3PAO engagement |
| CM — Configuration Management | **Shared** | System: chart/CRD/baseline; Customer: cluster CM, admission of the chart |
| CP — Contingency Planning | **Shared** | System: app DR runbooks/PDBs; CSP: infra resilience; Customer: etcd/CRD backup |
| IA — Identification and Authentication | **Shared** | System: service-to-service identity; Customer: human IdP/OIDC, MFA |
| IR — Incident Response | **Shared** | System: alerts/detections; Customer: IR program, reporting authority |
| MA — Maintenance | **Shared** | System: upgrade procedure; Customer: maintenance program; CSP: hardware MA |
| MP — Media Protection | **Customer-Responsibility / CSP-Inherited** | CSP: media sanitization/disposal; Customer: org media policy |
| PE — Physical and Environmental Protection | **CSP-Inherited** | Wholly inherited from hosting CSP |
| PL — Planning | **System-Implemented** | System: SSP, architecture, rules of behavior |
| PM — Program Management | **Customer-Responsibility** | Organizational program; System feeds inventory/POA&M |
| PS — Personnel Security | **Customer-Responsibility** | HR/org screening; System provides only PS-1 policy |
| RA — Risk Assessment | **Shared** | System: threat model, scanning; Customer: cluster/org RA |
| SA — System and Services Acquisition | **Shared** | System: SDLC, SBOM; Customer: acquisition/SLA of CSP |
| SC — System and Communications Protection | **Shared** | System: TLS/crypto/boundary; Customer: CNI, etcd-at-rest, apiserver TLS |
| SI — System and Information Integrity | **Shared** | System: flaw remediation, monitoring; Customer: cluster patching |
| SR — Supply Chain Risk Management | **Shared** | System: signing/provenance/SBOM; Customer: registry, admission verification |

Every FedRAMP-Moderate family above has an explicit allocation, satisfying the
acceptance requirement that no family is left unallocated.

---

## Per-family allocation detail

Each family below lists the allocation, the dominant System status from the
[control matrix](control-matrix.csv), and the remediation phase (P1–P12) where the
System portion is closed. Customer and CSP portions are not closed by repository work.

### AC — Access Control

- **Allocation:** Shared.
- **System part (status: Partial → P3):** The admission webhook (`AST-WH`) and
  policy-manager API (`AST-PM`) enforce policy-based admission control; the
  shipped chart (`AST-CHART`) bundles a namespace-scoped ServiceAccount and RBAC.
  Today the management/enforcement planes are effectively unauthenticated; OIDC/authZ
  on `AST-PM:8080`/`AST-DB:8090` and least-privilege SA are remediated in **P3**.
  Dashboard read-only default (write-gated by `ALLOW_WRITES`) is a bright spot
  already in place (`cmd/dashboard/proxy.go`).
- **Customer part:** Cluster RBAC for human users outside the chart, kube-apiserver
  authentication/authorization mode, OIDC IdP selection and account lifecycle (AC-2),
  node/host login access, and remote-access controls (AC-17) are Customer-Responsibility.
- See [Customer Responsibilities](#customer-responsibilities).

### AT — Awareness and Training

- **Allocation:** Customer-Responsibility (System provides AT-1 policy only).
- **System part (status: Planned → P9/P12):** The AT-1 policy artifact is authored
  in the compliance tree; the System delivers no training content or records.
- **Customer part:** The customer organization builds, delivers, and records
  role-based security awareness training (AT-2, AT-3, AT-4). This is not
  repository-resolvable.

### AU — Audit and Accountability

- **Allocation:** Shared.
- **System part (status: Partial → P3/P7):** Kube-Policies emits structured admission
  **decision audit records** (information type IT-2; `internal/audit`) with allow/deny
  attribution and exception suppression (`suppressed_by`). Current gaps — source
  attribution, tamper-evidence, durable storage (audit writes to `emptyDir`),
  retention enforcement, and SIEM forwarding — are remediated in **P3** (source/identity)
  and **P7** (durability, integrity, retention, forwarding).
- **Customer part:** kube-apiserver audit policy and audit-log storage, time
  synchronization (AU-8) at the node/cluster, and the SIEM/log-aggregation
  destination and its retention storage are Customer-Responsibility (the System
  forwards to a customer-provided endpoint once P7 lands).

### CA — Assessment, Authorization & Monitoring

- **Allocation:** Shared.
- **System part (status: Partial → P0/P12):** The System authors the SSP
  ([SSP](ssp/SSP.md)), this CRM, the [control matrix](control-matrix.csv), the SAP
  scaffolding, the interconnection register ([interconnections](interconnections.md)),
  and the ConMon plan. Interconnections CA-3 are documented (`ICX-01..06`).
- **Customer part:** The **ATO authorization decision** (CA-6), engaging an
  Independent Assessor / 3PAO (CA-2), and operating organizational continuous
  monitoring (CA-7) are Customer-Responsibility and cannot be self-implemented by
  the product.

### CM — Configuration Management

- **Allocation:** Shared.
- **System part (status: Partial → P0/P5):** The System ships a documented
  secure-configuration baseline (CM-2/CM-6) citing the controlling Helm value /
  manifest field for each hardened setting, the Helm chart and CRDs as the
  configuration artifacts (`AST-CHART`, `AST-CRD-POL`, `AST-CRD-EXC`), and a least-
  functionality posture (CM-7) via distroless images. Component inventory (CM-8)
  is the [inventory](inventory.csv). Chart hardening gaps (seccomp, `runAsGroup`,
  SA-token) are closed in **P5**.
- **Customer part:** The customer's own cluster configuration-management process,
  the decision to admit/deploy this chart, change control for cluster-wide settings,
  and any GitOps pipeline that applies the chart are Customer-Responsibility.

### CP — Contingency Planning

- **Allocation:** Shared.
- **System part (status: Planned → P8):** Application-level resilience — PodDisruptionBudgets,
  anti-affinity, and DR runbooks for the namespace workloads — is delivered in **P8**.
- **CSP part:** Infrastructure availability, power, and facility continuity are
  **CSP-Inherited**.
- **Customer part:** **etcd / CRD data backup and restore** (the `Policy`/`PolicyException`
  objects are stored in the customer's etcd, `ICX-06`), cluster-level backup tooling,
  and the organizational Contingency Plan (CP-2) and its testing (CP-4) are
  Customer-Responsibility.

### IA — Identification and Authentication

- **Allocation:** Shared.
- **System part (status: Partial → P2/P3):** Service-to-service identity — apiserver
  mTLS to the webhook (`ICX-01`), audience-bound token for `AST-WH → AST-PM` (`ICX-02`),
  and least-privilege ServiceAccount identity (`ICX-06`) — is implemented in **P2/P3**.
  No FIPS-validated module exists today (blocks IA crypto assurance until **P2**).
- **Customer part:** Human user identification and authentication to the cluster and
  to the dashboard, the **OIDC Identity Provider** selection and operation, MFA
  (IA-2(1)/(2)), and authenticator management (IA-5) are Customer-Responsibility.

### IR — Incident Response

- **Allocation:** Shared.
- **System part (status: Planned → P9):** Detection, alerting rules, and Alertmanager
  routing for the System workloads are delivered in **P9** (today alerts route to a
  dead `127.0.0.1` receiver — a tracked gap).
- **Customer part:** The organizational Incident Response Plan (IR-1/IR-8), incident
  handling and reporting to the authorizing authority (IR-4/IR-6), and the receiving
  SOC/SIEM are Customer-Responsibility.

### MA — Maintenance

- **Allocation:** Shared.
- **System part (status: Planned → P9/P12):** A documented upgrade/maintenance
  procedure for the chart and images (MA-2 at the application layer) is delivered in
  the operations runbooks.
- **CSP part:** Hardware and infrastructure maintenance, including controlled
  maintenance of the physical estate (MA-2/MA-3/MA-5 at the infrastructure layer),
  is **CSP-Inherited**.
- **Customer part:** The organizational maintenance program, controlled/remote
  maintenance authorization for cluster operators (MA-4), and maintenance-personnel
  controls are Customer-Responsibility.

### MP — Media Protection

- **Allocation:** Customer-Responsibility / CSP-Inherited (System provides MP-1 policy only).
- **CSP part:** Media sanitization (MP-6) and physical media storage/transport/disposal
  (MP-2/MP-4/MP-5) of the underlying storage media are **CSP-Inherited** from the
  hosting CSP's FedRAMP authorization.
- **Customer part:** The organizational media-protection policy (MP-1) tailoring,
  media access/marking (MP-2/MP-3) for any exported audit or policy data, and
  device-removal controls are Customer-Responsibility. Kube-Policies handles no
  removable media.

### PE — Physical and Environmental Protection

- **Allocation:** CSP-Inherited (wholly).
- **Basis:** Kube-Policies operates no physical facilities, power, fire suppression,
  or environmental controls. The **entire PE family** (PE-1 through PE-18) is inherited
  from the **hosting CSP's** existing FedRAMP-authorized data centers. The customer
  must reference the specific hosting CSP's FedRAMP Moderate authorization package in
  their own SSP and confirm the inheritance with that CSP. In the
  [control matrix](control-matrix.csv) these rows carry `responsible_party=CSP` and
  `status=Inherited`. No System or Customer action implements PE controls; the
  Customer's only action is to **document the inheritance** (see
  [Customer Responsibilities](#customer-responsibilities)).

### PL — Planning

- **Allocation:** System-Implemented.
- **System part (status: Partial → P0/P12):** The System authors the SSP
  ([SSP](ssp/SSP.md)), the PL-8 security architecture description, the rules of
  behavior, and this CRM. Finalization of narratives is completed in **P12**.
- **Customer part:** The customer adopts the planning artifacts into their own ATO
  package; no separate operator action beyond acceptance.

### PM — Program Management

- **Allocation:** Customer-Responsibility.
- **System part (status: Planned → P0):** The System feeds the program with the
  component [inventory](inventory.csv) (PM-5) and the [POA&M](poam.csv) (PM-4).
- **Customer part:** The organizational information-security program, the senior
  security officer designation, and program-level risk management (PM-1..PM-11) are
  Customer-Responsibility and are organizational, not repository-resolvable.

### PS — Personnel Security

- **Allocation:** Customer-Responsibility (System provides PS-1 policy only).
- **System part (status: Planned → P0):** Only the PS-1 policy artifact and a
  roles RACI are authored.
- **Customer part:** Position-risk designation (PS-2), personnel screening (PS-3),
  termination/transfer (PS-4/PS-5), access agreements (PS-6), and third-party personnel
  controls (PS-7) are HR/organizational and Customer-Responsibility.

### RA — Risk Assessment

- **Allocation:** Shared.
- **System part (status: Partial → P0/P11):** The System authors the categorization
  (RA-2, [FIPS-199](categorization/FIPS-199.md)), the canonical STRIDE
  [threat model](threat-model.md) (RA-3) — per-`ICX-01..06` STRIDE tables mapping each
  threat to a control and (where open) a [POA&M](poam.csv) item — and delivers
  vulnerability scanning (RA-5) that gates the build in **P11** (today scanning is
  non-gating — a tracked gap).
- **Customer part:** Cluster-level and organizational risk assessment, the acceptance
  of residual risk in the ATO, and risk-response decisions are Customer-Responsibility.

### SA — System and Services Acquisition

- **Allocation:** Shared.
- **System part (status: Partial → P1/P6/P11):** The System implements the secure
  SDLC (SA-3/SA-8/SA-15), developer testing (SA-11), and supply-chain SBOM/provenance
  (SA-12 family via **P6**). CI trustworthiness is established in **P1**.
- **Customer part:** Acquisition of and the service-level agreement with the hosting
  CSP (SA-9 external system services), and the customer's own acquisition process for
  this product, are Customer-Responsibility.

### SC — System and Communications Protection

- **Allocation:** Shared.
- **System part (status: Partial → P2/P3/P4):** The webhook serves **TLS 1.3** today
  (`AST-WH:8443`, bright spot; SC-8/SC-13). Boundary protection (SC-7) is the
  namespace boundary plus NetworkPolicy delivered in **P4**; FIPS-validated cryptography
  (SC-13) is delivered in **P2**; in-transit protection on the API/dashboard/metrics
  planes (currently plaintext HTTP) is delivered in **P3/P4**.
- **Customer part:** **kube-apiserver TLS configuration**, **etcd encryption-at-rest**
  (SC-28), the **CNI network plugin** that enforces NetworkPolicy (SC-7), control-plane
  certificate management, and key-management infrastructure (SC-12) are
  Customer-Responsibility.
- See [Customer Responsibilities](#customer-responsibilities).

### SI — System and Information Integrity

- **Allocation:** Shared.
- **System part (status: Partial → P2/P6/P7/P9/P11):** Flaw remediation (SI-2) via
  the vulnerability-management program (**P11**), malicious-code/image scanning (SI-3)
  via **P6**, monitoring (SI-4) via **P9**, and information-input validation (SI-10) in
  the admission engine (`AST-OPA`) are System-Implemented. Distroless images and
  `readOnlyRootFilesystem` on the dashboard pod are bright spots already present.
- **Customer part:** Cluster-level and node-level patching (SI-2 at the OS/kubelet
  layer), and the customer's monitoring/alerting destination, are Customer-Responsibility.

### SR — Supply Chain Risk Management

- **Allocation:** Shared.
- **System part (status: Partial → P1/P6/P11):** Image signing (cosign), SLSA
  provenance, SBOM generation, and action/base-image pinning are delivered in **P6**
  (today signing is scaffolding only — a tracked gap). Distroless base images
  (`AST-IMG-WH`, `AST-IMG-PM`, `AST-IMG-DB`) reduce supply-chain surface.
- **Customer part:** The container **registry** the customer pulls from, registry
  access controls, and **admission-time signature/provenance verification policy** in
  their cluster (which can be enforced by Kube-Policies itself once **P10** rules land)
  are Customer-Responsibility.

---

## Customer Responsibilities

The following are the concrete actions the **adopting cluster operator (Customer)**
must perform; none are implemented by the shipped chart (`AST-CHART`). These map to
the `responsible_party=Customer` (or the Customer side of `Shared`) rows in the
[control matrix](control-matrix.csv).

### Cluster control plane (SC, AU, IA)

1. **kube-apiserver TLS** — Configure the kube-apiserver to serve TLS 1.2+ (prefer 1.3)
   with managed certificates, enable mutating/validating admission plugins, and
   configure apiserver→webhook client-certificate (mTLS) trust so `ICX-01` is mutually
   authenticated. *(SC-8, SC-13, IA-9)*
2. **etcd encryption-at-rest** — Enable an `EncryptionConfiguration` (e.g., `aescbc`/`kms`)
   so the `Policy`/`PolicyException` CRD objects and Secrets stored in etcd
   (`ICX-06`) are encrypted at rest; on managed control planes confirm the provider
   enables this. *(SC-28)*
3. **kube-apiserver audit policy** — Define and apply an audit policy and route the
   apiserver audit log to durable storage; correlate with the System's decision
   audit records once SIEM forwarding lands. *(AU-2, AU-3, AU-6, AU-9)*
4. **Time synchronization** — Ensure cluster nodes synchronize to an authoritative
   time source so audit timestamps are trustworthy. *(AU-8)*

### Node and host hardening (CM, SC, SI)

5. **Node hardening** — Harden worker/control-plane node OS to the CIS Kubernetes
   Benchmark §4 (kubelet) and node-OS benchmark, restrict node SSH/login access, and
   apply OS patching. *(CM-6, SI-2, AC-3)*
6. **kubelet TLS and authn/authz** — Enable kubelet server TLS, disable anonymous
   auth, and enforce kubelet authorization (CIS §4.2). *(SC-8, IA-2)*

### Identity and access outside the chart (AC, IA)

7. **Cluster RBAC outside the chart** — Define RBAC for human users and external
   automation that interacts with the cluster and with the `Policy`/`PolicyException`
   CRDs; do not rely on the chart's namespace-scoped ServiceAccount for human access.
   *(AC-2, AC-3, AC-6)*
8. **OIDC / Identity Provider** — Select and operate an OIDC IdP for the cluster and
   for dashboard login (once P3 OIDC support ships), and enforce MFA for privileged
   operators. *(IA-2, IA-2(1), IA-5, AC-2)*

### Network (SC, AC)

9. **Network CNI / NetworkPolicy enforcement** — Run a CNI plugin that enforces
   Kubernetes `NetworkPolicy` (e.g., Calico, Cilium) so the NetworkPolicies shipped in
   **P4** actually constrain `ZONE-SYS` traffic; without an enforcing CNI, NetworkPolicy
   objects are inert. *(SC-7, AC-4)*

### Data protection and continuity (CP, SC, SR)

10. **etcd / CRD backup and restore** — Back up etcd (or the managed-control-plane
    equivalent) so `Policy`/`PolicyException` state is recoverable, and test restore.
    *(CP-9, CP-10)*
11. **Container registry and image verification** — Operate the registry the chart
    images are pulled from, pin image digests in Helm values, and configure
    admission-time signature/provenance verification. *(SR-3, SR-4, CM-14)*

### Organizational programs (AT, IR, PM, PS, RA, MA, MP, CA)

12. **Security awareness training program** — Build, deliver, and record role-based
    training. *(AT-2, AT-3, AT-4)*
13. **Incident Response program** — Stand up an IR plan and a SOC/SIEM to receive the
    System's alerts and forwarded audit records; define reporting to the authorizing
    authority. *(IR-1, IR-4, IR-6, IR-8)*
14. **Personnel security** — Perform position-risk designation, screening, and
    access agreements for cluster operators. *(PS-2, PS-3, PS-6, PS-7)*
15. **Program and risk management** — Operate the organizational security program,
    accept residual risk, and own the cluster/organizational risk assessment.
    *(PM-1..PM-11, RA-1)*
16. **Maintenance program** — Authorize and log controlled/remote maintenance of the
    cluster. *(MA-2, MA-4)*

### CSP inheritance (PE, MP, CP, MA — environmental)

17. **Document CSP inheritance** — In the customer's own SSP, cite the **hosting CSP's**
    FedRAMP Moderate authorization package and claim the inherited **PE family**
    (PE-1..PE-18, physical/environmental), the infrastructure portions of **MP** (media
    sanitization/disposal), **CP** (facility/power continuity), and **MA** (hardware
    maintenance). Confirm the inheritance scope with the CSP. *(PE-1, MP-6, CP-8, MA-3)*

---

## Cross-reference and consistency

- This CRM's allocations are authoritative for the [control matrix](control-matrix.csv)
  `responsible_party` column: System-Implemented → `System`, CSP-Inherited → `CSP`,
  Customer-Responsibility → `Customer`, Shared → `Shared`. No allocation here may
  conflict with that column; if a discrepancy is found, the control matrix and this
  CRM are reconciled together at review time.
- Remediation phases (P1–P12) cited here match the
  [control matrix](control-matrix.csv) `remediating_phase` column and the
  [POA&M](poam.csv) entries.
- Component, port, trust-zone, and interconnection identifiers (`AST-*`, `ZONE-*`,
  `ICX-*`) are used verbatim from the [system facts](system-facts.md).
- Related artifacts: [SSP](ssp/SSP.md), [FIPS-199 categorization](categorization/FIPS-199.md),
  [POA&M](poam.csv), [inventory](inventory.csv), [interconnections](interconnections.md).
