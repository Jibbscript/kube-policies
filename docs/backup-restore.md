---
title: "Backup and Restore — Kube-Policies (KP)"
controls: "CP-9, CP-9(1), CP-10"
version: "0.1.0"
status: "Draft"
owner: "System Owner (TBD — assign)"
approver: "Authorizing Official (TBD — assign)"
last_reviewed: "2026-06-01"
next_review: "2027-06-01"
---

# Backup and Restore — Kube-Policies (KP)

This document covers the backup and restore posture for the Kube-Policies system under **NIST SP
800-53 Rev 5 CP-9 / CP-10** (FedRAMP Moderate) and **CIS Kubernetes Benchmark 1.1.x** (etcd
controls). It is the operational companion to the state model described in
[docs/state-model.md](state-model.md).

> **Scope:** Kube-Policies is presently a proof-of-concept not yet authorized (no ATO). The
> procedures below document the backup *discipline* the program targets and the controls that are
> *actually implemented* — not a claim that every control is fully operating or assessed. Open
> weaknesses are tracked in [`docs/compliance/POAM.md`](compliance/POAM.md) (POAM-010–013).

---

## 1. Overview and State Model

The authoritative runtime state of Kube-Policies consists of:

| Object kind | API group | What it holds |
|---|---|---|
| `Policy` | `policies.kube-policies.io` | Admission policy rules and their enforcement mode |
| `PolicyException` | `policies.kube-policies.io` | Scoped, time-bounded exceptions to policies |
| Webhook configurations | `admissionregistration.k8s.io` | Which API resources KP intercepts |

All three are persisted as Kubernetes API objects and therefore live **inside etcd** — the
control-plane key-value store. etcd is thus the single source of truth for cluster policy state.

See [docs/state-model.md](state-model.md) for the full state model, including the relationship
between in-cluster CRs, the admission webhook, and the policy-manager reconciliation loop.

**Backup strategy depends on cluster type:**

| Cluster type | etcd access | Customer backup responsibility |
|---|---|---|
| Self-managed (kubeadm, bare-metal) | Full access | etcd snapshot + CRD export (§ 2) |
| Managed (EKS / GKE / AKS) | Provider-managed, no access | CRD-level export only (§ 3) |

---

## 2. Self-Managed Control Plane: etcd Snapshot Save and Restore

On self-managed clusters the operator has direct access to the etcd data directory and TLS
credentials, enabling full etcd snapshots under CIS 1.1.x controls.

### 2.1 Prerequisites

- `etcdctl` installed and in `PATH` (same minor version as the running etcd).
- TLS credentials readable: `/etc/kubernetes/pki/etcd/ca.crt`, `server.crt`, `server.key`
  (kubeadm defaults; adjust via flags or env vars).
- Sufficient disk space at the snapshot destination.

### 2.2 Taking a Snapshot

```bash
# Using defaults (kubeadm PKI paths, local endpoint):
scripts/backup/etcd-snapshot.sh

# Override endpoints/certs explicitly:
scripts/backup/etcd-snapshot.sh \
  --endpoints https://127.0.0.1:2379 \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert   /etc/kubernetes/pki/etcd/server.crt \
  --key    /etc/kubernetes/pki/etcd/server.key \
  --out    /backup/etcd-snapshot-$(date -u +%Y%m%dT%H%M%SZ).db

# Preview the exact etcdctl command without executing (dry-run):
scripts/backup/etcd-snapshot.sh --dry-run
```

The script (`scripts/backup/etcd-snapshot.sh`):

1. Validates that `etcdctl` is present and all cert paths exist.
2. Runs `ETCDCTL_API=3 etcdctl snapshot save <path>`.
3. Immediately runs `etcdctl snapshot status` to confirm integrity.
4. Reminds the operator to `chmod 0600` the snapshot file (CIS 1.1.11).

**CIS 1.1.x mappings for snapshot files:**

| CIS control | Requirement | How addressed |
|---|---|---|
| 1.1.11 | etcd data dir permissions 0700 | `chmod 0700` applied to restored dir by `etcd-restore.sh` |
| 1.1.12 | etcd data dir ownership (etcd user) | Printed reminder in `etcd-restore.sh` post-restore guidance |
| 2.1 | etcd peer TLS | `--cacert`/`--cert`/`--key` flags enforced; no plaintext endpoint |
| 2.2 | etcd client TLS | Same — `etcdctl` invoked with full mTLS; no `--insecure-*` flags |

> **Encryption at rest (CIS 1.2.31 / NIST SC-28):** etcd-level encryption at rest is configured
> via the Kubernetes `EncryptionConfiguration` API resource on the kube-apiserver
> (`--encryption-provider-config`), not by etcdctl. Snapshots taken while encryption is enabled
> will contain encrypted data. Ensure the `EncryptionConfiguration` is backed up separately
> alongside the snapshot so decryption keys are available during restore.

### 2.3 Restoring from a Snapshot

```bash
# Restore to /var/lib/etcd-restore (default), then follow the printed manual steps:
sudo scripts/backup/etcd-restore.sh \
  --snapshot /backup/etcd-snapshot-20260601T000000Z.db

# Specify all parameters explicitly (multi-node cluster):
sudo scripts/backup/etcd-restore.sh \
  --snapshot /backup/etcd-snapshot-20260601T000000Z.db \
  --data-dir /var/lib/etcd-restore \
  --name control-plane-1 \
  --initial-cluster "control-plane-1=https://10.0.0.1:2380,control-plane-2=https://10.0.0.2:2380" \
  --initial-advertise-peer-urls https://10.0.0.1:2380 \
  --initial-cluster-token etcd-cluster-restored

# Preview (dry-run):
scripts/backup/etcd-restore.sh --snapshot /backup/snapshot.db --dry-run
```

The script (`scripts/backup/etcd-restore.sh`):

1. Validates prerequisites and that the snapshot file exists.
2. Runs `ETCDCTL_API=3 etcdctl snapshot restore` into `--data-dir`.
3. Applies `chmod 0700` to the restored directory (CIS 1.1.11).
4. Prints step-by-step guidance for the manual control-plane swap (stop static Pod, swap data
   dirs, restart, verify health).

**The operator must perform the printed manual steps** — the script restores the data directory
only; moving it into production and restarting etcd is a deliberate human gate.

### 2.4 Backup Schedule Recommendation

For production self-managed clusters, automate snapshots with a CronJob or systemd timer running
`etcd-snapshot.sh` on a schedule aligned with the organization's RPO. Encrypt and replicate the
resulting `.db` files to off-cluster storage (S3, GCS, Azure Blob, or equivalent). Retain at
minimum 30 days of snapshots.

---

## 3. Managed Control Planes (EKS, GKE, AKS)

On **managed Kubernetes services** the etcd data store is **provider-managed** and is **not
accessible** to cluster operators. There is no etcd endpoint, no PKI directory, and no
`etcdctl snapshot save` capability for the customer.

**Customer backup responsibility is scoped to the Kubernetes API objects** — specifically the
`Policy` and `PolicyException` custom resources that define the policy state of Kube-Policies.

### 3.1 Scheduled CRD Backup via Helm Chart (RES-WU-13)

The Kube-Policies Helm chart ships an optional `CronJob` that:

1. Exports all `Policy` and `PolicyException` CRs cluster-wide to YAML (via an `initContainer`
   running `kubectl get -A -o yaml`).
2. Uploads the YAML to an S3-compatible object store (via an `aws-cli` container).
3. Uses a least-privilege read-only `ServiceAccount` — no write or delete permissions required.

The CronJob is defined in
[`charts/kube-policies/templates/backup-cronjob.yaml`](../charts/kube-policies/templates/backup-cronjob.yaml).

**Enabling the CronJob:**

```bash
helm upgrade kube-policies charts/kube-policies \
  --set backup.enabled=true \
  --set backup.s3.bucket=my-backup-bucket \
  --set backup.s3.region=us-east-1 \
  --set backup.s3.existingSecret=kube-policies-backup-creds
```

The `existingSecret` must contain keys `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` for an
IAM principal with `s3:PutObject` on the target bucket. Bucket lifecycle policies (not the
CronJob) enforce the `backup.retentionDays` retention; the CronJob itself never deletes objects.
Backup staleness is monitored via `kube_cronjob_status_last_successful_time` (see RES-WU-11
alerting).

Key values (see `charts/kube-policies/values.yaml` under `backup:`):

| Value | Default | Description |
|---|---|---|
| `backup.enabled` | `false` | Enable the CronJob |
| `backup.schedule` | `"0 */6 * * *"` | Cron schedule (UTC, every 6 h) |
| `backup.s3.bucket` | `""` | Required when enabled |
| `backup.s3.region` | `us-east-1` | S3 region |
| `backup.s3.prefix` | `kube-policies` | Object key prefix |
| `backup.s3.endpoint` | `""` | S3-compatible endpoint (MinIO/Ceph); empty = AWS S3 |
| `backup.s3.existingSecret` | `""` | Required when enabled |
| `backup.retentionDays` | `30` | Documents bucket lifecycle policy retention |

### 3.2 Velero Alternative

[Velero](https://velero.io/) is a popular open-source Kubernetes backup tool that can back up and
restore namespaced and cluster-scoped API objects (including CRDs and CRs) independently of etcd
access. It is a suitable alternative or complement to the built-in CronJob for managed clusters:

```bash
# Install Velero with AWS plugin (adjust for GCS/Azure):
velero install \
  --provider aws \
  --plugins velero/velero-plugin-for-aws:v1.9.0 \
  --bucket my-backup-bucket \
  --backup-location-config region=us-east-1 \
  --secret-file ./credentials-velero

# Create an on-demand backup of Kube-Policies CRDs and CRs:
velero backup create kube-policies-backup \
  --include-resources policies.policies.kube-policies.io,policyexceptions.policies.kube-policies.io \
  --include-cluster-resources=true

# Restore:
velero restore create --from-backup kube-policies-backup
```

### 3.3 Manual CRD Export and Restore (One-liners)

For ad-hoc or emergency backup/restore without the CronJob or Velero:

```bash
# Export all Policy / PolicyException CRs (cluster-scoped), stripping the
# server-populated fields + status so the artifact re-applies cleanly on a fresh
# cluster (a raw `kubectl get -o yaml` dump carries resourceVersion/uid/status and
# can be rejected on restore). This is the SAME sanitize the scheduled CronJob
# performs (RES-WU-13) so its S3 artifact is already restore-ready.
STRIP='del(.items[].metadata.resourceVersion, .items[].metadata.uid, .items[].metadata.creationTimestamp, .items[].metadata.generation, .items[].metadata.managedFields, .items[].status)'
kubectl get policies.policies.kube-policies.io -A -o yaml | yq eval "$STRIP" - > policies-backup.yaml
kubectl get policyexceptions.policies.kube-policies.io -A -o yaml | yq eval "$STRIP" - > policyexceptions-backup.yaml

# Restore (the sanitized artifact applies cleanly; idempotent):
kubectl apply -f policies-backup.yaml
kubectl apply -f policyexceptions-backup.yaml
```

> The scheduled CRD-backup CronJob (RES-WU-13) writes an ALREADY-SANITIZED artifact
> to object storage, so disaster recovery from it is a direct `kubectl apply -f`
> of the downloaded files — no extra strip step. The `yq` strip above is only for
> ad-hoc manual exports taken with a bare `kubectl get -o yaml`.
>
> The backup → delete → restore equivalence of the sanitized artifact is proven by
> `test/e2e/backup_restore_test.go` (RES-WU-14). Store exported YAML off-cluster;
> they are the minimal artefacts needed to reconstruct the policy configuration on
> any cluster that has Kube-Policies installed.

---

## 4. CIS Kubernetes Benchmark 1.1.x Mapping

| CIS Control | Description | How Addressed |
|---|---|---|
| 1.1.11 | Ensure that the etcd data directory permissions are set to 700 or more restrictive | `etcd-restore.sh` applies `chmod 0700` to the restored data directory and prints a reminder for the live dir |
| 1.1.12 | Ensure that the etcd data directory ownership is set to etcd:etcd | `etcd-restore.sh` prints ownership guidance; operator sets `chown etcd:etcd` post-restore |
| 2.1 | Ensure that the `--cert-file` and `--key-file` arguments are set as appropriate for etcd | `etcd-snapshot.sh` and `etcd-restore.sh` require `--cacert`/`--cert`/`--key` and use mTLS — no insecure flags permitted |
| 2.2 | Ensure that the `--client-cert-auth` argument is set to true | Enforced by providing client certs; the scripts do not support unauthenticated access |
| 2.3 | Ensure that the `--auto-tls` argument is not set to true | Scripts use explicit PKI paths only — auto-TLS is never passed |
| 2.4 | Ensure that the `--peer-cert-file` and `--peer-key-file` arguments are set | Peer TLS is an etcd server configuration concern; snapshot/restore scripts address client TLS only — peer TLS is verified via the etcd static Pod manifest |
| 2.7 | Ensure that a unique Certificate Authority is used for etcd | Scripts parameterize `--cacert` with the dedicated etcd CA (`/etc/kubernetes/pki/etcd/ca.crt`), separate from the kube API CA |

---

## 5. Related Documents

- [docs/state-model.md](state-model.md) — etcd as source of truth, state model overview
- [docs/compliance/POAM.md](compliance/POAM.md) — open backup-related weaknesses (POAM-010–013)
- [`scripts/backup/etcd-snapshot.sh`](../scripts/backup/etcd-snapshot.sh) — snapshot script
- [`scripts/backup/etcd-restore.sh`](../scripts/backup/etcd-restore.sh) — restore script
- [`charts/kube-policies/templates/backup-cronjob.yaml`](../charts/kube-policies/templates/backup-cronjob.yaml) — scheduled CRD backup CronJob (RES-WU-13)
- [`charts/kube-policies/values.yaml`](../charts/kube-policies/values.yaml) — `backup.*` values
