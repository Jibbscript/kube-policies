# Kube-Policies State Model

> Controls: NIST CP-2, CP-9, CP-10 · CIS Kubernetes 1.1.x (etcd) · RES-WU-08
> Status: Draft · Last reviewed: 2026-06-01

This document describes where kube-policies keeps its state, why the control-plane
components are effectively stateless, and what that means for high availability,
scaling, backup, and recovery.

## Summary

**The Policy and PolicyException custom resources, stored in the cluster's etcd,
are the single source of truth.** Every kube-policies component rebuilds its
working state from those CRDs (plus its bundled default policies) on startup. No
component requires a PersistentVolume to operate, and losing a pod loses no policy
state.

| Component | In-process state | Persisted to disk? | Source of truth |
|-----------|------------------|--------------------|-----------------|
| admission-webhook | in-memory OPA engine (policies + exceptions) | No | Policy/PolicyException CRDs (etcd) + bundled defaults |
| policy-manager | in-memory registry served by `/api/v1/policies`, `/api/v1/exceptions` | No | Policy/PolicyException CRDs (etcd) + bundled defaults |
| dashboard | none (read-only BFF; proxies the policy-manager) | No | policy-manager API |

The audit log is a separate concern (see [Audit storage](#audit-storage)).

## Why the policy-manager has no required PersistentVolume (RES-WU-08)

Historically the chart mounted a `ReadWriteOnce` PVC at `/var/lib/kube-policies`
for the policy-manager. **No code path ever wrote to it.** The manager
(`internal/policymanager/manager.go`) holds policies, bundles, and exceptions in
maps guarded by a mutex; CRD reconcilers (`internal/policymanager/controller.go`)
upsert/remove entries from those maps as the apiserver reports CRD changes. The
only file the manager reads is the audit log, which has its own mount.

A `ReadWriteOnce` volume can be attached to pods on only one node at a time. With
the HA default of `policyManager.replicaCount: 2` (RES-WU-03) a RWO PVC would
prevent the second replica from scheduling. Because the volume was unused, the
chart now **defaults `persistence.enabled: false`**, and a render-time guard
(`_helpers.tpl`) refuses to pair a RWO persistence PVC with `replicaCount > 1`.

If a future feature needs on-disk caching, enable persistence with **either**
`policyManager.replicaCount: 1` **or** `persistence.accessMode: ReadWriteMany`
backed by a shared StorageClass (NFS/EFS/CephFS).

## High availability and leaderless reconciliation (RES-WU-03)

Both the admission-webhook and the policy-manager default to multiple replicas and
run their CRD reconcilers **leaderless** (`LeaderlessReconcilers: true`): every
replica watches the Policy/PolicyException CRDs and maintains its own in-memory
copy. Consequences:

- A `kubectl apply` of a Policy becomes visible from **every** replica's
  `/api/v1/policies` within one reconcile pass — reads are consistent regardless
  of which pod the Service routes to.
- Killing the leader (the pod holding the `coordination.k8s.io/Lease`) does **not**
  stall reconciliation: the survivors keep reconciling because reconcile is not
  gated on the lease.
- The manager-level Lease is still acquired for observability and to elect the
  single replica that emits reconcile-driven **audit** events (so a config change
  is audited once, not once per replica — see `auditWhenLeader` in
  `controller.go`).
- Status-subresource patch races between replicas are benign: each writes the same
  spec-derived `Phase`/`Conditions` via an idempotent merge patch.

## Restart and recovery behavior

On (re)start each component:

1. Loads its **bundled default policies** (unless `--disable-default-policies`).
2. Connects to the apiserver and **lists + watches** Policy and PolicyException
   CRDs, rebuilding its in-memory registry/engine from etcd.

Therefore:

- **Pod loss / rollout / node failure:** no policy state is lost; a fresh pod
  reconstructs identical state from etcd. The forced-restart recovery test
  (`test/e2e/state_recovery_test.go`, RES-WU-19, CP-10(2)) asserts the system
  returns to a known-good configuration within the documented RTO.
- **etcd loss:** Policy/PolicyException CRDs are lost. Recover them from an etcd
  snapshot or from the scheduled CRD backup (see below). This is the scenario the
  contingency plan's RPO targets.

## Backup and restore

Two complementary mechanisms protect the source of truth:

- **CRD-level backup (customer-owned):** the scheduled CronJob (RES-WU-13,
  `charts/kube-policies/templates/backup-cronjob.yaml`) exports all Policy and
  PolicyException CRs to off-cluster object storage on a schedule. This is the
  recommended mechanism on managed control planes (EKS/GKE/AKS) where etcd is
  provider-managed.
- **etcd snapshot (cluster-owned):** for self-managed control planes, full etcd
  snapshot/restore (`scripts/backup/etcd-snapshot.sh` /
  `scripts/backup/etcd-restore.sh`, RES-WU-12) captures Policy/PolicyException
  state along with the rest of the cluster.

The backup→delete→restore equivalence is proven by
`test/e2e/backup_restore_test.go` (RES-WU-14, CP-9/CP-10(2)).

See [docs/backup-restore.md](backup-restore.md),
[docs/contingency-plan.md](contingency-plan.md), and
[docs/runbooks/disaster-recovery.md](runbooks/disaster-recovery.md).

## Audit storage

The audit log is independent of the policy state model. By default each webhook
pod writes to an ephemeral `emptyDir`; durable retention is provided by an opt-in
audit PVC (`audit.persistence`) and/or off-cluster forwarding (`audit.forwarder`).
See the audit documentation (AUD-WU-08/10) for the durability/forwarding tradeoffs
and the `ReadWriteOnce` + multi-replica caveat that applies there too.
