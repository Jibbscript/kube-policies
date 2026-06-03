---
title: "Contingency Plan (CP-2 / CP-9 / CP-10) — Kube-Policies (KP)"
control_family: "CP — Contingency Planning"
controls: "CP-2, CP-6, CP-9, CP-10"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Contingency Plan — Kube-Policies (KP)

This is the **compliance-artifact contingency plan (CP-2)** for the Kube-Policies system
(KP), categorized **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5** (FedRAMP **Moderate**
baseline). It is the CP-2 artifact referenced by the [CP policy](../policies/CP-policy.md)
and the [SSP](../ssp/SSP.md). The operational version of this plan — including failure
scenarios, roles, and the tabletop exercise checklist — is
[docs/contingency-plan.md](../../contingency-plan.md). The step-by-step recovery runbooks
are in [docs/runbooks/disaster-recovery.md](../../runbooks/disaster-recovery.md). Do not
duplicate or contradict those documents; this artifact provides the structured CP-2 fields
and the per-control compliance evidence trace.

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. The RTO/RPO values in this
document are design targets verified in automated e2e tests — they have not been demonstrated
in a live production environment. Per-control status is tracked in the
[control matrix](../control-matrix.csv) and open weaknesses in the [POA&M](../POAM.md).

**Annual review.** This plan is reviewed and updated at least **annually**. The last review
was **2026-06-01**; the **next review is 2027-06-01**. Reviews are recorded by updating the
`last_reviewed`/`next_review` front-matter and the version. The plan is also reviewed after
any disruption event, after a tabletop exercise that reveals gaps, or after a significant
change to the resilience controls.

## 1 Purpose, scope, and essential functions

### 1.1 Purpose (CP-2)

The purpose of this plan is to ensure that KP can be restored to a known-good, fully
operational state within defined recovery objectives following any disruption affecting
the system or its source of truth (Policy/PolicyException CRDs in etcd).

### 1.2 Scope

This plan covers:

- All KP authorization-boundary components: admission-webhook (`AST-WH`), policy-manager
  (`AST-PM`), dashboard (`AST-DB`/`AST-SPA`).
- The Policy and PolicyException CRDs (etcd) — the single source of truth for all policy
  state (see [docs/state-model.md](../../state-model.md)).
- The CRD-backup CronJob (`charts/kube-policies/templates/backup-cronjob.yaml`, RES-WU-13)
  and the etcd snapshot scripts (`scripts/backup/etcd-snapshot.sh`,
  `scripts/backup/etcd-restore.sh`).

Audit log backup and retention is governed by the [AU policy](../policies/AU-policy.md)
and is a separate concern from policy-state recovery.

### 1.3 Essential missions and business functions

| Function | Description | Priority |
|---|---|---|
| **Admission enforcement** | The admission webhook evaluates every `CREATE`/`UPDATE` request against the loaded Policy set and renders an allow/deny decision (fail-closed on webhook unavailability). | Critical |
| **Policy management** | The policy-manager serves the management API for Policy/PolicyException CRUD; supports compliance-report generation. | High |
| **Dashboard** | Read-only BFF for the policy-manager API; not in the admission critical path. | Normal |

## 2 Recovery objectives (CP-2)

| Objective | Value | Assumptions |
|---|---|---|
| **RTO** | **30 minutes** | Helm + kubectl available; backup artifact on-hand; responder has cluster access. Validated by `test/e2e/state_recovery_test.go` (RES-WU-19). |
| **RPO** — managed cluster | **≤ 24 hours** (objective); **≈ 6 hours** at the chart default | RPO equals the configured `backup.schedule` interval of the CRD-backup CronJob (RES-WU-13); the chart default is every 6 hours (`"0 */6 * * *"`). 24 h is the objective ceiling. Latest backup available in object storage. |
| **RPO** — self-managed etcd | **Near-zero** | etcd snapshot interval equals the RPO; `scripts/backup/etcd-snapshot.sh` / `etcd-restore.sh`. |

These values are consistent with [docs/contingency-plan.md](../../contingency-plan.md) §1
and [docs/compliance/policies/CP-policy.md](../policies/CP-policy.md) §3.1.

## 3 Roles and responsibilities (CP-2)

| Role | Holder | Contingency responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for plan adequacy; authorizes alternate-site activation; approves deviations. |
| ISSO | TBD — assign before assessment | Designated CP official; initiates plan activation; documents events and lessons learned; maintains the POA&M. |
| Operator / SRE | TBD — assign | Executes DR runbook; performs backup/restore; reports status to ISSO. |
| Cluster Operator (customer) | TBD (Customer) | Manages cluster-level recovery (etcd, control plane, nodes). |
| Authorizing Official (AO) | TBD — assign before assessment | Notified of events; approves re-authorization after significant configuration changes. |

Contacts (e.g., `isso@kube-policies.io`) are **placeholders** pending role assignment.

## 4 Backup and restore procedures (CP-9 / CP-10)

### 4.1 Policy and PolicyException CRD state

**Source of truth.** Policy/PolicyException CRDs in etcd. Components are stateless: every
replica rebuilds its in-memory registry from etcd on startup; no PersistentVolume is
required for the admission-webhook or policy-manager (see [state-model.md](../../state-model.md)).

**CRD-level backup (managed clusters, CP-9 / RES-WU-13).**
The scheduled CronJob (`charts/kube-policies/templates/backup-cronjob.yaml`) exports
Policy and PolicyException CRs to S3-compatible object storage. This is the recommended
mechanism for managed control planes (EKS/GKE/AKS). The backup is **opt-in** (default-off
in the chart); enabling it requires object-storage configuration. Backup frequency and
retention are operator-configured.

**etcd snapshot (self-managed clusters, CP-9).**
`scripts/backup/etcd-snapshot.sh` captures the full etcd state including KP CRDs.
Snapshots must be stored off-cluster (object storage or equivalent). Restore is via
`scripts/backup/etcd-restore.sh`.

**Backup verification (CP-9).** The backup→delete→restore equivalence is validated by
`test/e2e/backup_restore_test.go` (RES-WU-14).

**Residual.** The CRD-backup CronJob is opt-in and default-off; a deployment without it
enabled has no automated CRD-level backup and relies on etcd snapshots or manual
`kubectl get … -o yaml` exports. This is tracked in the [POA&M](../POAM.md).

### 4.2 Policy-manager persistence (opt-in, default-off)

The policy-manager does not require a PersistentVolume: its in-memory state is always
reconstructed from etcd on startup. `persistence.enabled` defaults to `false`. If a
future feature enables on-disk caching, the persistence PVC contents are not a source
of truth and are not subject to this backup procedure — etcd backup covers the
authoritative state.

### 4.3 Audit log backup

Audit log backup is a separate concern governed by the [AU policy](../policies/AU-policy.md).
The opt-in audit PVC and the off-cluster forwarding path (both default-off) provide
durable audit retention; see POAM-010/011/012.

## 5 Fail-closed webhook behavior as a contingency consideration (CP-2)

The admission webhook validate path uses `failurePolicy: Fail` (fail-closed). When no
webhook replica is available, all new admission requests to the cluster are denied. This is
intentional — it prevents policy-bypass during an outage — but operators must plan for it:

- Existing running workloads are unaffected.
- During recovery, if the cluster must accept new workloads before KP is restored, the
  webhook can be temporarily set to `failurePolicy: Ignore` per the DR runbook
  ([docs/runbooks/disaster-recovery.md#all-replicas-loss](../../runbooks/disaster-recovery.md#all-replicas-loss)).
  This **must** be documented as a deviation in the POA&M and reversed immediately after
  recovery.
- The mutate path uses `failurePolicy: Ignore` (fail-open).

## 6 Contingency plan testing (CP-2)

### 6.1 Automated e2e tests

| Test | Work unit | Controls | What it validates |
|---|---|---|---|
| `test/e2e/state_recovery_test.go` | RES-WU-19 | CP-10(2) | Forced restart → system returns to known-good state within the documented RTO. |
| `test/e2e/backup_restore_test.go` | RES-WU-14 | CP-9, CP-10 | Backup → delete → restore equivalence for Policy/PolicyException CRDs. |

### 6.2 Annual tabletop exercise

An annual tabletop exercise is conducted against the checklist in
[docs/contingency-plan.md](../../contingency-plan.md) §6. The exercise tests the
operability of the DR runbook procedures and the accuracy of the RTO/RPO assumptions.
Findings are documented and, where they reveal gaps, create or update POA&M entries.

The next tabletop exercise is due by **2027-06-01**.

## 7 Alternate processing site (CP-6 / CP-7)

For deployments requiring a warm-standby alternate processing site, see
[docs/high-availability.md](../../high-availability.md) §3. Because KP policy state
lives in etcd-backed CRDs (no PV migration required), setting up a warm standby requires
only: (a) deploying KP at the alternate site with the same Helm chart and values, and
(b) synchronizing Policy/PolicyException CRDs via GitOps or the CRD-backup restore path.

## 8 Honest scope and residual gaps

This plan claims only what is implemented:

- **Implemented (Partial):** CP-2 (this plan + operational plan + DR runbook; tabletop
  exercise checklist; annual review statement). Partial because roles are not yet staffed
  (TBD) and the plan has not been exercised in a live production environment.
- **Implemented (Partial):** CP-9 (CRD-backup CronJob + etcd snapshot scripts + e2e
  backup-restore test). Partial because the CronJob is opt-in/default-off; no automated
  backup runs by default.
- **Implemented:** CP-10 (state reconstruction from etcd on restart; forced-restart e2e
  test; full-reinstall DR runbook).
- **No ATO.** PoC on the path to readiness; not in production use; RTO/RPO not demonstrated
  in a live cluster.

## 9 References

- CP policy: [../policies/CP-policy.md](../policies/CP-policy.md)
- Contingency plan — operational: [docs/contingency-plan.md](../../contingency-plan.md)
- DR runbook: [docs/runbooks/disaster-recovery.md](../../runbooks/disaster-recovery.md)
- High availability guide: [docs/high-availability.md](../../high-availability.md)
- Backup and restore guide: [docs/backup-restore.md](../../backup-restore.md)
- State model: [docs/state-model.md](../../state-model.md)
- CRD backup CronJob: `charts/kube-policies/templates/backup-cronjob.yaml`
- etcd scripts: `scripts/backup/etcd-snapshot.sh`, `scripts/backup/etcd-restore.sh`
- e2e tests: `test/e2e/state_recovery_test.go`, `test/e2e/backup_restore_test.go`
- AU policy (audit backup): [../policies/AU-policy.md](../policies/AU-policy.md)
- Control matrix: [../control-matrix.csv](../control-matrix.csv) · POA&M: [../POAM.md](../POAM.md)
- SSP: [../ssp/SSP.md](../ssp/SSP.md) · Compliance index: [../README.md](../README.md)
- NIST SP 800-53 Rev 5 (CP-2, CP-6, CP-9, CP-10); FedRAMP Moderate baseline; FIPS-199.
