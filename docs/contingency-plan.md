# Contingency Plan — Kube-Policies (KP)

> NIST SP 800-53 Rev 5: CP-2, CP-7 · RES-WU-15
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01
> Owner: System Owner (TBD — assign) · Approver: Authorizing Official (TBD — assign)

This is the **operational contingency plan** for the Kube-Policies system (KP). It defines
recovery objectives, failure scenarios, roles, and the recovery procedures that operators
execute during and after a disruption. The companion compliance artifact is
[docs/compliance/plans/contingency-plan.md](compliance/plans/contingency-plan.md); the
step-by-step recovery runbooks are in
[docs/runbooks/disaster-recovery.md](runbooks/disaster-recovery.md).

Kube-Policies is a **Proof-of-Concept being driven to FedRAMP-Moderate readiness**; it is
**not yet authorized** (**no ATO**) and not in production use. The RTO/RPO values below are
design targets, verified in automated e2e tests — they have not been demonstrated in a live
production environment.

## 1 Recovery objectives

| Objective | Value | Basis and assumptions |
|---|---|---|
| **RTO** (Recovery Time Objective) | **30 minutes** | Time from declared disruption to webhook accepting admission requests again. Assumes Helm + kubectl available, backup artifact on-hand, and responder has cluster access. Validated by `test/e2e/state_recovery_test.go` (RES-WU-19). |
| **RPO** (Recovery Point Objective) — managed cluster | **≤ 24 hours** (objective); **≈ 6 hours** at the chart default | Maximum policy-state data loss when recovering from the scheduled CRD-backup CronJob (RES-WU-13, `charts/kube-policies/templates/backup-cronjob.yaml`). The effective RPO equals the configured `backup.schedule` interval — the chart default is every 6 hours (`"0 */6 * * *"`), so the default RPO is ≈ 6 h; 24 h is the objective ceiling. Assumes the latest backup is in object storage. |
| **RPO** — self-managed etcd with snapshots | **Near-zero** | etcd snapshot/restore (`scripts/backup/etcd-snapshot.sh` / `scripts/backup/etcd-restore.sh`) captures Policy/PolicyException CRDs along with the full cluster state. RPO equals the interval between the last etcd snapshot and the failure event. |

**Assumptions and scope.**
- The cluster control plane (apiserver, etcd, scheduler, controller-manager) is operational
  or is being recovered in parallel. KP depends on the apiserver; a full etcd rebuild
  precedes KP-level recovery.
- Object storage (S3-compatible) for the CRD backup is available and accessible from within
  the cluster.
- The Helm chart, CRDs, and OCI image are available from their respective registries or a
  local mirror.
- Network access from the recovery operator to the cluster is available.

## 2 Failure scenarios

### 2.1 Single node loss

**Impact.** Pod(s) on the lost node are rescheduled by the Kubernetes controller. KP
defaults to `replicaCount: 2` for both the admission-webhook and the policy-manager
(RES-WU-03); the PodDisruptionBudget (RES-WU-01/02) limits simultaneous disruptions.
Soft pod anti-affinity and `topologySpreadConstraints` (RES-WU-04) prevent both replicas
from landing on the same node under normal conditions.

**Recovery.** Kubernetes self-heals. Each new pod rebuilds its in-memory policy registry
by listing/watching Policy and PolicyException CRDs from etcd — no policy state is lost
(see [state-model.md](state-model.md)). Operator action is not required unless both
replicas were on the failed node.

**RTO.** Typically < 5 minutes (Kubernetes pod scheduling + startup probe clearance,
RES-WU-05/06).

### 2.2 Availability-zone loss

**Impact.** Pods scheduled in the lost AZ are rescheduled. If `topologySpreadConstraints`
placed replicas across AZs (RES-WU-04), at least one replica survives.

**Recovery.** Same self-heal path as §2.1. If all replicas were in the lost AZ, the
full-reinstall path (§2.4 of the DR runbook) restores service once AZ recovery or
rescheduling completes. Policy state is intact in etcd as long as the etcd quorum was
maintained.

### 2.3 etcd loss (self-managed cluster)

**Impact.** All CRD state — Policy and PolicyException resources — is lost. In-flight
webhook replicas continue serving from their in-memory registry until they restart; any
restart drains that in-memory state permanently.

**Recovery.** Restore etcd from snapshot (`scripts/backup/etcd-restore.sh`) or, if no
etcd snapshot is available, restore Policy/PolicyException CRDs from the CRD-backup
CronJob artifact. See [runbooks/disaster-recovery.md#etcd-loss](runbooks/disaster-recovery.md#etcd-loss).

**RPO.** Equals the age of the most recent etcd snapshot (near-zero with automated
snapshots; up to 24 hours if falling back to CRD backup).

### 2.4 Full control-plane loss (self-managed)

**Impact.** KP is non-functional; the fail-closed `failurePolicy: Fail` on the validate
webhook causes all admission requests to fail (see §5). Managed clusters (EKS/GKE/AKS)
are provider-recovered; KP CRD state is recovered from the CRD backup afterward.

**Recovery.** Restore the control plane per the cluster operator's procedure, then restore
KP CRD state. See [runbooks/disaster-recovery.md#full-reinstall](runbooks/disaster-recovery.md#full-reinstall).

### 2.5 Webhook TLS certificate expiry

**Impact.** The apiserver cannot contact the admission webhook over TLS; all admission
requests fail (fail-closed). `cert-manager` (or the chart's built-in `certgen` Job)
normally handles rotation automatically.

**Recovery.** Rotate the TLS certificate and update the webhook `caBundle`. See
[runbooks/disaster-recovery.md#cert-rotation](runbooks/disaster-recovery.md#cert-rotation)
and [docs/runbooks/cert-rotation.md](cert-rotation.md) for the full procedure.

### 2.6 All-replicas loss (admission-webhook)

**Impact.** No webhook replica is running; fail-closed means all new admission requests
fail. Existing running workloads are unaffected.

**Recovery.** Restart or redeploy the admission-webhook. Each fresh replica rebuilds its
in-memory registry from etcd within one reconcile pass. See
[runbooks/disaster-recovery.md#all-replicas-loss](runbooks/disaster-recovery.md#all-replicas-loss).

**RTO.** < 5 minutes from pod scheduling to readiness probe clearance, assuming etcd and
the apiserver are healthy.

## 3 Fail-closed behavior as a contingency consideration

The admission webhook validate path uses `failurePolicy: Fail` (fail-closed). During a
recovery event — while no webhook replica is available — **all new admission requests to
the cluster are denied**. Operators must be aware of this:

- Existing running workloads are not affected (admission only applies to new or updated
  objects).
- If the cluster must continue accepting workloads during KP recovery, the webhook can be
  temporarily disabled: `kubectl delete validatingwebhookconfiguration kube-policies-webhook`
  (document as a deviation, re-enable immediately after recovery).
- The mutate path uses `failurePolicy: Ignore` (fail-open); mutation failures do not block
  admission.

## 4 Alternate processing site (warm standby)

For deployments requiring a warm-standby alternate processing site (CP-7):

- Deploy KP to a secondary cluster with the same Helm chart and values.
- Synchronize Policy and PolicyException CRDs to the secondary cluster either by:
  - Configuring the CRD-backup CronJob to write to shared object storage and running a
    periodic restore Job on the secondary, **or**
  - Using GitOps tooling (Flux/ArgoCD) to reconcile the same Policy/PolicyException
    manifests to both clusters from a shared repository.
- The secondary cluster is ready to serve admission traffic once KP is deployed and the
  CRDs are applied (no PV migration required — see [state-model.md](state-model.md)).

See [docs/high-availability.md](high-availability.md) for minimum replica and zone
requirements at the alternate site.

## 5 Roles and responsibilities

| Role | Holder | Contingency responsibility |
|---|---|---|
| System Owner | TBD — assign before assessment | Accountable for contingency plan adequacy; authorizes activation of the alternate processing site; approves deviations (e.g. temporary webhook disable). |
| ISSO | TBD — assign before assessment | Initiates plan activation; coordinates recovery activities; documents the event, deviations, and lessons learned; updates the POA&M. |
| Operator / SRE | TBD — assign | Executes the DR runbook procedures; performs and verifies backup/restore operations; reports status to ISSO. |
| Cluster Operator (customer) | TBD (Customer) | Manages cluster-level recovery (etcd, control plane, node replacement); provides access and credentials needed for KP recovery. |
| Authorizing Official (AO) | TBD — assign before assessment | Notified of disruption events; approves re-authorization if the recovery introduced significant configuration changes. |

Contacts (e.g., `isso@kube-policies.io`) are **placeholders** pending role assignment.

## 6 Tabletop exercise checklist

The following checklist is used for annual tabletop exercises and for post-incident review:

- [ ] Can the team locate and access the latest CRD backup artifact in object storage?
- [ ] Can the team locate and access the latest etcd snapshot (if self-managed)?
- [ ] Are the DR runbook steps current and accurate?
- [ ] Are Helm chart + image references pinned to a known-good version?
- [ ] Has the state-recovery e2e test (`test/e2e/state_recovery_test.go`) passed on the
      current codebase?
- [ ] Has the backup-restore e2e test (`test/e2e/backup_restore_test.go`) passed?
- [ ] Can the operator complete etcd restore within the 30-minute RTO?
- [ ] Is the fail-closed webhook behavior documented in the incident runbook and understood
      by all on-call responders?
- [ ] Are all role assignments in §5 current (not TBD)?
- [ ] Were any deviations taken during the exercise? If so, are they recorded in the POA&M?

## 7 Annual review

This plan is reviewed and updated at least **annually**. The last review was **2026-06-01**;
the **next review is 2027-06-01**. It is also reviewed after any disruption event, after a
significant change to the system's resilience controls (PDB, replica count, backup mechanism,
failurePolicy), or following a tabletop exercise that reveals gaps. Reviews are recorded by
updating the header dates and incrementing the version.

## 8 References

- DR runbook (step-by-step recovery): [docs/runbooks/disaster-recovery.md](runbooks/disaster-recovery.md)
- High availability guide: [docs/high-availability.md](high-availability.md)
- Backup and restore guide: [docs/backup-restore.md](backup-restore.md)
- State model (etcd as source of truth): [docs/state-model.md](state-model.md)
- Compliance artifact (CP-2): [docs/compliance/plans/contingency-plan.md](compliance/plans/contingency-plan.md)
- TLS certificate rotation: [docs/runbooks/cert-rotation.md](runbooks/cert-rotation.md)
- CRD backup CronJob: `charts/kube-policies/templates/backup-cronjob.yaml`
- etcd backup scripts: `scripts/backup/etcd-snapshot.sh`, `scripts/backup/etcd-restore.sh`
- e2e recovery tests: `test/e2e/state_recovery_test.go`, `test/e2e/backup_restore_test.go`
- POA&M: [docs/compliance/POAM.md](compliance/POAM.md)
- NIST SP 800-53 Rev 5: CP-2, CP-6, CP-7, CP-9, CP-10; FedRAMP Moderate baseline.
