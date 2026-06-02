---
title: "Contingency Planning Policy (CP) — Kube-Policies (KP)"
control_family: "CP — Contingency Planning"
controls: "CP-1, CP-2, CP-6, CP-9, CP-10"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Contingency Planning Policy (CP) — Kube-Policies (KP)

This policy establishes the Contingency Planning requirements for the Kube-Policies system
(KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate**
baseline). It implements control **CP-1 (Policy and Procedures)** and anchors the CP controls
that govern how KP detects, responds to, and recovers from disruptions: **CP-2** (Contingency
Plan), **CP-6** (Alternate Storage Site), **CP-9** (Information System Backup), and **CP-10**
(Information System Recovery and Reconstitution). The operational plan is the
[contingency plan](../../contingency-plan.md); the compliance-artifact version is the
[contingency plan (compliance)](../plans/contingency-plan.md); the step-by-step recovery
procedures are in [docs/runbooks/disaster-recovery.md](../../runbooks/disaster-recovery.md).

Kube-Policies is presently a **Proof-of-Concept being driven to assessment readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. This policy claims **only what
the shipped code and chart implement**. Per-control status is tracked in the
[control matrix](../control-matrix.csv) and open weaknesses in the [POA&M](../POAM.md), with
remediation phases (P0–P12) defined in `.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`.

**Annual review.** This policy is reviewed and updated at least **annually**. The last review
was **2026-06-01**; the **next review is 2027-06-01**. It is also reviewed whenever a
significant change occurs to the resilience controls (replica counts, PDB, backup mechanism,
failurePolicy, RTO/RPO targets) or the applicable standards. Reviews are recorded by updating
the `last_reviewed`/`next_review` front-matter and the version.

## 1 Purpose and applicability

The purpose of this policy is to ensure that KP can be restored to a known-good operating
state within defined time and data-loss objectives following any disruption, and that
contingency planning activities are documented, tested, and maintained.

It applies to:

- All KP authorization-boundary components in the `kube-policies-system` namespace:
  the admission-webhook (`AST-WH`), policy-manager (`AST-PM`), and dashboard (`AST-DB`/`AST-SPA`).
- The Policy and PolicyException CRDs stored in etcd — the single source of truth for all
  policy state (see [docs/state-model.md](../../state-model.md)).
- The CRD-backup CronJob (`charts/kube-policies/templates/backup-cronjob.yaml`, RES-WU-13)
  and the etcd snapshot scripts (`scripts/backup/etcd-snapshot.sh`,
  `scripts/backup/etcd-restore.sh`).
- All personnel filling the System Owner, ISSO, Operator, and Maintainer roles.

Named roles are **not yet staffed**; this policy refers to them by title with the qualifier
"TBD — assign before assessment" and does not name individuals (see
[roles-raci.md](../roles-raci.md)). All `@kube-policies.io` contacts are **placeholders**.

## 2 CP-1 — Contingency Planning Policy and Procedures

### 2.1 Policy statement

The KP program shall develop, document, and disseminate this CP policy and the procedures
needed to implement it; shall designate an official to manage them; and shall review and
update both on a defined frequency. This document is that policy; the operational procedures
are in [docs/contingency-plan.md](../../contingency-plan.md) (operational version) and
[docs/compliance/plans/contingency-plan.md](../plans/contingency-plan.md) (compliance
artifact); the step-by-step recovery runbooks are in
[docs/runbooks/disaster-recovery.md](../../runbooks/disaster-recovery.md).

### 2.2 CP-1(a) — Scope and recipients

This policy applies to the scope in §1. It is disseminated to the System Owner, ISSO, AO,
Maintainers, and all repository contributors by being maintained in version control under
`docs/compliance/policies/` and referenced from the SSP ([ssp/SSP.md](../ssp/SSP.md), CP
family) and the compliance index ([README.md](../README.md)).

### 2.3 CP-1(b) — Designated official

The **ISSO (TBD — assign before assessment)** is designated to manage, review, and update
this policy and its procedures, with the **System Owner (TBD — assign before assessment)**
accountable for adequacy and resourcing.

### 2.4 CP-1(c) — Review and update frequency

| Artifact | Owner role | Review frequency | Event triggers |
|---|---|---|---|
| This CP policy (CP-1) | ISSO | At least annually (next: 2027-06-01) | RTO/RPO change; resilience-control change; assessor finding |
| Contingency plan — operational ([contingency-plan.md](../../contingency-plan.md)) | ISSO | At least annually (next: 2027-06-01) | Post-incident; tabletop exercise finding; significant system change |
| Contingency plan — compliance ([plans/contingency-plan.md](../plans/contingency-plan.md)) | ISSO | At least annually (next: 2027-06-01) | Aligned with operational plan update |
| DR runbook ([runbooks/disaster-recovery.md](../../runbooks/disaster-recovery.md)) | Operator | Per system change + annually | Procedure drift; new recovery scenario; tool/script change |

## 3 CP-2 — Contingency Plan

### 3.1 Plan requirement

KP shall maintain a contingency plan that:

- Identifies the essential missions and business functions KP supports and the associated
  continuity requirements (admission-control enforcement is the essential function).
- Defines recovery objectives: **RTO 30 minutes**, **RPO 24 hours** (managed-cluster CRD
  backup) / **near-zero** (self-managed etcd snapshot).
- Enumerates the failure scenarios and their recovery procedures (node loss, AZ loss, etcd
  loss, control-plane loss, certificate expiry, all-replicas loss).
- Identifies roles and responsibilities (§5 of the operational plan).
- Includes a tabletop exercise checklist and an annual test/review statement.

The plan is maintained in [docs/contingency-plan.md](../../contingency-plan.md) and
cross-referenced by [docs/compliance/plans/contingency-plan.md](../plans/contingency-plan.md).

### 3.2 Fail-closed behavior

The admission webhook validate path uses `failurePolicy: Fail`. During a recovery event
in which no webhook replica is available, all new admission requests to the cluster are
denied. This is a documented contingency consideration in the operational plan (§3 of
[docs/contingency-plan.md](../../contingency-plan.md)) and must be understood by all
on-call responders. The mutate path uses `failurePolicy: Ignore`.

## 4 CP-6 — Alternate Storage Site

Policy state is stored as Policy/PolicyException CRDs in etcd (the cluster's native etcd).
Two off-cluster storage mechanisms provide alternate storage:

- **CRD-backup CronJob (RES-WU-13):** exports Policy/PolicyException CRs to S3-compatible
  object storage on a configurable schedule (default daily). Object storage is
  geographically separate from the primary cluster.
- **etcd snapshots (self-managed):** `scripts/backup/etcd-snapshot.sh` produces full etcd
  snapshots that can be written to object storage or other off-cluster media.

The alternate storage site strategy supports the **24-hour RPO** target (managed-cluster
CRD backup) and **near-zero RPO** (etcd snapshots). See
[docs/high-availability.md](../../high-availability.md) §3 for the multi-cluster warm-standby
strategy that uses the alternate storage path for policy-state synchronization.

## 5 CP-9 — Information System Backup

KP shall protect policy state through regular backups:

- **CRD-level backup (CP-9, RES-WU-13).** The scheduled CronJob (`backup-cronjob.yaml`)
  exports all Policy and PolicyException CRs to off-cluster object storage. Recommended
  on managed control planes (EKS/GKE/AKS) where etcd is provider-managed.
- **etcd snapshot (CP-9).** For self-managed clusters, `scripts/backup/etcd-snapshot.sh`
  captures full etcd state including KP CRDs. Snapshots shall be stored off-cluster
  (object storage or equivalent).
- **Backup verification (CP-9).** The backup→delete→restore equivalence is validated by
  `test/e2e/backup_restore_test.go` (RES-WU-14).
- **Audit logs.** The audit log is a separate concern with its own backup path (opt-in
  audit PVC and/or off-cluster forwarding — see the [AU policy](AU-policy.md)).

**Residual.** The CRD backup CronJob is opt-in (default-off in the chart); it must be
enabled and configured with object-storage credentials before it provides CP-9 coverage.
This is a tracked gap (see [POA&M](../POAM.md)).

## 6 CP-10 — Information System Recovery and Reconstitution

KP shall recover to a known-good state following a disruption:

- **State reconstruction from etcd (CP-10).** On any restart, each KP component rebuilds
  its in-memory policy registry by listing and watching Policy/PolicyException CRDs from
  etcd. No persistent volume or manual intervention is required for a pod-level restart.
  See [docs/state-model.md](../../state-model.md).
- **Forced-restart state recovery (CP-10(2), RES-WU-19).** The e2e test
  `test/e2e/state_recovery_test.go` asserts that after a forced restart, the system returns
  to a known-good configuration within the documented RTO.
- **Backup-driven restore (CP-10).** `scripts/backup/etcd-restore.sh` restores a full etcd
  snapshot. CRD-level restore is via `kubectl apply` of the CronJob backup artifact.
  Verified by `test/e2e/backup_restore_test.go`.
- **Full reinstall (CP-10).** The DR runbook
  ([docs/runbooks/disaster-recovery.md#full-reinstall](../../runbooks/disaster-recovery.md#full-reinstall))
  provides an ordered `helm install` + CRD-restore procedure for full rebuild scenarios.

## 7 Roles and responsibilities (summary)

| Role | Holder | CP responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for contingency plan adequacy and resourcing; authorizes alternate-site activation; approves this policy. |
| ISSO | TBD — assign before assessment | Designated official managing this policy/plan/procedures; initiates plan activation; documents events and lessons learned; maintains the POA&M for CP findings. |
| Operator / SRE | TBD — assign | Executes DR runbook procedures; performs and verifies backup/restore; reports to ISSO. |
| Cluster Operator (customer) | TBD (Customer) | Manages cluster-level recovery (etcd, control plane, node replacement). |
| Authorizing Official (AO) | TBD — assign before assessment | Approves the SSP; notified of disruption events; approves re-authorization if recovery introduced significant configuration changes. |

## 8 Compliance, exceptions, and enforcement

- Disabling the PDBs or reducing `replicaCount` below 2 in a production environment is a
  deviation requiring ISSO acknowledgement and a POA&M entry.
- Changing `failurePolicy` from `Fail` to `Ignore` on the validate webhook is a deviation
  requiring System Owner approval and a POA&M entry (except as a temporary recovery measure
  per the DR runbook).
- Skipping the annual contingency-plan test/review requires System Owner and ISSO approval
  and a POA&M entry.
- Nothing in this artifact constitutes an authorization to operate.

## 9 References

- Contingency plan — operational: [docs/contingency-plan.md](../../contingency-plan.md)
- Contingency plan — compliance: [docs/compliance/plans/contingency-plan.md](../plans/contingency-plan.md)
- DR runbook: [docs/runbooks/disaster-recovery.md](../../runbooks/disaster-recovery.md)
- High availability guide: [docs/high-availability.md](../../high-availability.md)
- Backup and restore guide: [docs/backup-restore.md](../../backup-restore.md)
- State model: [docs/state-model.md](../../state-model.md)
- CRD backup CronJob: `charts/kube-policies/templates/backup-cronjob.yaml`
- etcd scripts: `scripts/backup/etcd-snapshot.sh`, `scripts/backup/etcd-restore.sh`
- e2e tests: `test/e2e/state_recovery_test.go`, `test/e2e/backup_restore_test.go`
- Control matrix: [../control-matrix.csv](../control-matrix.csv) · POA&M: [../POAM.md](../POAM.md)
- SSP: [../ssp/SSP.md](../ssp/SSP.md) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (CP-1, CP-2, CP-6, CP-9, CP-10); FedRAMP Moderate baseline; FIPS-199.
