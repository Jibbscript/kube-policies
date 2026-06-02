# High Availability — Kube-Policies (KP)

> NIST SP 800-53 Rev 5: CP-2, CP-6, CP-7 · RES-WU-16
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01

This document specifies the minimum replica and zone requirements for a high-availability
KP deployment, describes the multi-AZ scheduling controls the chart ships by default, and
outlines a multi-cluster warm-standby strategy for deployments that require an alternate
processing site (CP-7).

For RTO/RPO objectives see [docs/contingency-plan.md](contingency-plan.md).
For recovery procedures see [docs/runbooks/disaster-recovery.md](runbooks/disaster-recovery.md).
For state architecture (why no PV is required) see [docs/state-model.md](state-model.md).

## 1 Minimum replica requirements

| Component | Default `replicaCount` | Minimum for HA | Notes |
|---|---|---|---|
| `admission-webhook` | 2 | 2 | Below 2 leaves no redundancy; PDB enforces `minAvailable: 1` (RES-WU-01). |
| `policy-manager` | 2 | 2 | Below 2 leaves no redundancy; PDB enforces `minAvailable: 1` (RES-WU-02). |
| `dashboard` | 1 | 1 | Read-only BFF; not in the admission critical path. Increase to 2 if dashboard availability is required. |

**Leaderless reconcilers.** Both the admission-webhook and the policy-manager run
leaderless CRD reconcilers (RES-WU-03): every replica independently watches
Policy/PolicyException CRDs and maintains its own in-memory policy registry. Losing one
replica does not stall reconciliation on the survivors. See
[docs/state-model.md](state-model.md) for the full leaderless-reconciliation model.

**PodDisruptionBudgets (RES-WU-01/02).** The chart creates a PDB for each component.
With the default `minAvailable: 1`, a voluntary disruption (node drain, rolling upgrade)
is only permitted when at least one replica remains running. Involuntary disruptions (node
failure) are not blocked by PDBs but are mitigated by multi-AZ scheduling (§2).

**Opt-in HPA (RES-WU-18).** Horizontal Pod Autoscaling is available as an opt-in chart
value (`admissionWebhook.hpa.enabled`, `policyManager.hpa.enabled`). It is off by
default; enable it for production deployments with variable admission-request load.

**Opt-in PriorityClass (RES-WU-20).** A high-priority PriorityClass is available
(`admissionWebhook.priorityClassName`, `policyManager.priorityClassName`) to reduce
the likelihood of KP pods being evicted under node pressure.

## 2 Multi-AZ scheduling

### 2.1 Soft pod anti-affinity (RES-WU-04)

The chart sets a **soft** (`preferredDuringSchedulingIgnoredDuringExecution`) pod
anti-affinity rule on both the admission-webhook and the policy-manager, expressing a
preference to avoid co-scheduling replicas on the same node. This is a best-effort
constraint: if only one node is available, scheduling proceeds rather than failing.

For production deployments spanning multiple AZs, upgrade the anti-affinity to
**required** (`requiredDuringSchedulingIgnoredDuringExecution`) with a `topologyKey` of
`topology.kubernetes.io/zone`:

```yaml
# values.yaml override for hard AZ anti-affinity
admissionWebhook:
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchLabels:
              app.kubernetes.io/component: admission-webhook
          topologyKey: topology.kubernetes.io/zone
policyManager:
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchLabels:
              app.kubernetes.io/component: policy-manager
          topologyKey: topology.kubernetes.io/zone
```

### 2.2 TopologySpreadConstraints (RES-WU-04)

The chart also sets `topologySpreadConstraints` to distribute replicas across AZs:

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/component: admission-webhook
```

`whenUnsatisfiable: ScheduleAnyway` is the default (soft). Change to
`DoNotSchedule` for hard enforcement in environments where multi-AZ node pools are
guaranteed.

**Minimum node topology for HA.** To avoid both replicas landing in the same AZ and
being lost in an AZ failure, the cluster must have nodes in at least **two**
availability zones. Three AZs is recommended for Moderate-baseline deployments.

### 2.3 Graceful drain (RES-WU-07)

The chart configures `terminationGracePeriodSeconds` and a native sleep `preStop` hook
on both components so that in-flight admission requests complete before the pod
terminates during rolling upgrades or node drains. The webhook binary also accepts a
`--shutdown-drain-delay` flag for extended drain windows. This ensures rolling updates
do not momentarily expose the cluster to a zero-replica window.

### 2.4 Startup and readiness probes (RES-WU-05/06)

Startup probes prevent a freshly-scheduled pod from receiving traffic before its
in-memory policy registry is fully rebuilt from etcd. The readiness probe on the
admission-webhook checks the `/readyz` endpoint over TLS; a pod fails readiness (and
is removed from the Service endpoints) if it cannot serve TLS-authenticated requests.
Together these ensure that only pods with a consistent, up-to-date policy registry
receive admission requests.

## 3 Multi-cluster warm-standby (alternate processing site, CP-7)

A warm-standby alternate processing site requires a second Kubernetes cluster with KP
deployed and its policy state synchronized from the primary. Because KP's policy state
lives entirely in etcd-backed CRDs (no PV required), setting up a warm standby is
straightforward:

### 3.1 Deploying KP at the alternate site

```bash
helm upgrade --install kube-policies charts/kube-policies \
  --namespace kube-policies-system \
  --create-namespace \
  --values values-primary.yaml \
  --kube-context <ALTERNATE_CLUSTER_CONTEXT> \
  --wait
```

The alternate-site deployment should use the same Helm values as the primary to ensure
policy enforcement is equivalent.

### 3.2 Synchronizing policy state (CRDs) to the alternate site

**Option A — GitOps (recommended).** Manage Policy and PolicyException manifests as
versioned YAML in a Git repository and use Flux or ArgoCD to reconcile them to both
clusters simultaneously. This gives continuous synchronization with no RPO gap.

**Option B — Scheduled CRD-backup restore.** Configure the CRD-backup CronJob
(RES-WU-13) to write backups to shared object storage. On the alternate cluster, run a
periodic restore Job that pulls the latest backup and applies it:

```bash
# On the alternate cluster — run periodically or on activation
aws s3 cp s3://<BUCKET>/<PREFIX>/latest/policies.yaml ./policies.yaml
aws s3 cp s3://<BUCKET>/<PREFIX>/latest/policyexceptions.yaml ./policyexceptions.yaml
kubectl apply -f policies.yaml --context <ALTERNATE_CLUSTER_CONTEXT>
kubectl apply -f policyexceptions.yaml --context <ALTERNATE_CLUSTER_CONTEXT>
```

With a daily CronJob schedule, the alternate site's policy state lags the primary by
at most **24 hours** (the RPO for managed-cluster CRD backup). For tighter RPO,
increase the CronJob frequency or use GitOps.

### 3.3 Activating the alternate site

1. Redirect cluster admission traffic to the alternate cluster (update DNS, load
   balancer, or cluster selector in the workload deployment tooling).
2. Verify KP webhook is operational on the alternate cluster:
   ```bash
   kubectl apply -f test/fixtures/allow-policy-test.yaml \
     --dry-run=server \
     --context <ALTERNATE_CLUSTER_CONTEXT>
   ```
3. Document the activation as a deviation in the POA&M if it was unplanned; notify
   the ISSO and System Owner.

## 4 Summary: HA requirements checklist

| Requirement | Chart default | Production recommendation |
|---|---|---|
| Webhook replicas | 2 | ≥ 2 across ≥ 2 AZs |
| Policy-manager replicas | 2 | ≥ 2 across ≥ 2 AZs |
| PDB minAvailable | 1 | 1 (or N/2 for larger deployments) |
| Pod anti-affinity | Soft (preferred) | Hard (required) for multi-AZ |
| TopologySpreadConstraints | ScheduleAnyway | DoNotSchedule for guaranteed multi-AZ |
| HPA | Off | On for variable load |
| PriorityClass | None | Set to prevent eviction under pressure |
| Leaderless reconcilers | Enabled | Keep enabled — required for HA |
| Persistence (policy-manager) | Off | Off (stateless by design) |
| Alternate-site synchronization | Not configured | GitOps or daily CRD-backup restore |

## 5 Annual review

This document is reviewed and updated at least **annually** (next review **2027-06-01**)
and whenever a significant change is made to the chart's resilience controls (replica
counts, PDB, anti-affinity, probes, drains) or the backup/restore path. Reviews are
recorded by updating the header dates.

## 6 References

- Contingency plan: [docs/contingency-plan.md](contingency-plan.md)
- DR runbook: [docs/runbooks/disaster-recovery.md](runbooks/disaster-recovery.md)
- Backup and restore guide: [docs/backup-restore.md](backup-restore.md)
- State model (leaderless reconciliation, no PV): [docs/state-model.md](state-model.md)
- CRD backup CronJob: `charts/kube-policies/templates/backup-cronjob.yaml`
- PDB manifests: `charts/kube-policies/templates/poddisruptionbudget.yaml`
- e2e tests: `test/e2e/state_recovery_test.go`, `test/e2e/backup_restore_test.go`
- NIST SP 800-53 Rev 5: CP-2, CP-6, CP-7, CP-9; FedRAMP Moderate baseline.
