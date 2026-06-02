# Disaster Recovery Runbook — Kube-Policies (KP)

> RES-WU-15 · NIST CP-2, CP-10
> Status: Draft · Last reviewed: 2026-06-01 · Next review: 2027-06-01

Ordered, copy-pasteable recovery procedures for Kube-Policies. Each section maps to a
failure scenario in [docs/contingency-plan.md](../contingency-plan.md). Alert
`runbook_url` annotations in the alert rules (shipped in P9) reference the anchored
section headers below.

**RTO: 30 minutes** from declared disruption to webhook accepting admission requests.
**RPO: 24 hours** (managed-cluster CRD backup) / **near-zero** (self-managed etcd
snapshot).

> Prerequisites for all procedures: `kubectl` configured for the target cluster,
> `helm` v3 available, cluster-admin or equivalent RBAC, and access to the object
> storage bucket used by the CRD-backup CronJob (if applicable).

---

## etcd-loss

**Scenario:** Policy and PolicyException CRDs are lost due to etcd corruption or
deletion. Self-managed cluster.

### Option A — Restore from etcd snapshot

1. Stop the kube-apiserver to prevent writes during restore:
   ```bash
   # On each control-plane node:
   mv /etc/kubernetes/manifests/kube-apiserver.yaml /tmp/kube-apiserver.yaml.bak
   ```

2. Run the etcd restore script on each control-plane node:
   ```bash
   SNAPSHOT_FILE=/path/to/etcd-snapshot.db \
   ETCD_DATA_DIR=/var/lib/etcd \
   bash scripts/backup/etcd-restore.sh
   ```
   The script stops etcd, restores the snapshot, and restarts etcd.

3. Restore the apiserver manifest:
   ```bash
   mv /tmp/kube-apiserver.yaml.bak /etc/kubernetes/manifests/kube-apiserver.yaml
   ```

4. Wait for the control plane to become ready:
   ```bash
   kubectl wait --for=condition=Ready node --all --timeout=300s
   ```

5. Verify Policy and PolicyException CRDs are present:
   ```bash
   kubectl get crds | grep kube-policies.io
   kubectl get policies -A
   kubectl get policyexceptions -A
   ```

6. Verify KP webhook is accepting requests:
   ```bash
   kubectl get pods -n kube-policies-system
   kubectl get validatingwebhookconfigurations kube-policies-webhook
   ```

7. Run a smoke test:
   ```bash
   kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
   ```

### Option B — Restore CRDs from CRD backup (etcd snapshot unavailable)

If no etcd snapshot is available, fall back to the CRD-level backup (see
[full-reinstall](#full-reinstall), steps 5–7).

---

## full-reinstall

**Scenario:** Full cluster rebuild, managed-cluster control-plane loss (EKS/GKE/AKS),
or etcd snapshot unavailable. Recover KP CRDs from the CRD-backup CronJob artifact.

1. Confirm the cluster control plane is healthy:
   ```bash
   kubectl cluster-info
   kubectl get nodes
   ```

2. Confirm the KP namespace and CRDs are absent (fresh install) or present (reinstall):
   ```bash
   kubectl get namespace kube-policies-system
   kubectl get crds | grep kube-policies.io
   ```

3. Install (or reinstall) the Helm chart:
   ```bash
   helm upgrade --install kube-policies charts/kube-policies \
     --namespace kube-policies-system \
     --create-namespace \
     --values your-values.yaml \
     --wait
   ```
   This creates the CRDs and deploys all KP components. Pods start with bundled default
   policies loaded from the binary; the custom Policy/PolicyException CRs are not yet
   restored.

4. Verify pods are running and ready:
   ```bash
   kubectl get pods -n kube-policies-system
   kubectl rollout status deployment/kube-policies-admission-webhook \
     -n kube-policies-system
   kubectl rollout status deployment/kube-policies-policy-manager \
     -n kube-policies-system
   ```

5. Retrieve the latest CRD backup from object storage. Replace `<BUCKET>` and
   `<PREFIX>` with the values from your CronJob configuration:
   ```bash
   # Example using AWS CLI:
   aws s3 cp s3://<BUCKET>/<PREFIX>/latest/policies.yaml ./policies-restore.yaml
   aws s3 cp s3://<BUCKET>/<PREFIX>/latest/policyexceptions.yaml \
     ./policyexceptions-restore.yaml
   ```

6. Remove cluster-scoped metadata fields that will conflict on re-apply:
   ```bash
   kubectl apply -f policies-restore.yaml
   kubectl apply -f policyexceptions-restore.yaml
   ```

7. Verify all policies and exceptions are loaded:
   ```bash
   kubectl get policies -A
   kubectl get policyexceptions -A
   ```

8. Confirm each KP replica has reconciled (watch logs for `UPSERT` events):
   ```bash
   kubectl logs -n kube-policies-system \
     -l app.kubernetes.io/component=policy-manager \
     --tail=50
   ```

9. Run a smoke test:
   ```bash
   kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
   ```

---

## cert-rotation

**Scenario:** Webhook TLS certificate expired or corrupted; apiserver cannot reach the
webhook; all admission requests fail (fail-closed).

For the full certificate rotation procedure (including `cert-manager` renewal and manual
fallback), see [docs/runbooks/cert-rotation.md](cert-rotation.md). The steps below are
the minimal emergency path.

1. Check whether `cert-manager` is managing the certificate:
   ```bash
   kubectl get certificate -n kube-policies-system
   kubectl describe certificate kube-policies-webhook-cert \
     -n kube-policies-system
   ```
   If the certificate shows `Ready: False`, trigger a manual renewal:
   ```bash
   kubectl annotate certificate kube-policies-webhook-cert \
     -n kube-policies-system \
     cert-manager.io/issuer-kind=ClusterIssuer --overwrite
   # Or using cmctl:
   cmctl renew kube-policies-webhook-cert -n kube-policies-system
   ```

2. If `cert-manager` is not in use, regenerate the TLS secret manually:
   ```bash
   # Delete the existing secret to trigger the chart's certgen Job:
   kubectl delete secret kube-policies-webhook-tls \
     -n kube-policies-system
   # Restart the certgen Job (adjust Job name per your chart version):
   kubectl delete job kube-policies-certgen -n kube-policies-system
   helm upgrade kube-policies charts/kube-policies \
     --namespace kube-policies-system \
     --reuse-values
   ```

3. Retrieve the new CA bundle and patch the webhook configuration:
   ```bash
   CA_BUNDLE=$(kubectl get secret kube-policies-webhook-tls \
     -n kube-policies-system \
     -o jsonpath='{.data.ca\.crt}')
   kubectl patch validatingwebhookconfiguration kube-policies-webhook \
     --type='json' \
     -p="[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\
   \"value\":\"${CA_BUNDLE}\"}]"
   ```

4. Verify the webhook is operational:
   ```bash
   kubectl get validatingwebhookconfiguration kube-policies-webhook \
     -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | base64 -d | \
     openssl x509 -noout -dates
   kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
   ```

---

## leader-reelection

**Scenario:** The policy-manager replica holding the `coordination.k8s.io/Lease` has
crashed or been evicted and reconciliation audit events have stalled.

KP runs **leaderless reconcilers** (RES-WU-03): every replica maintains its own in-memory
policy registry and continues reconciling regardless of the Lease. The Lease controls only
which replica emits audit events for reconcile operations (`auditWhenLeader`). In almost
all cases, no operator action is required.

1. Confirm surviving replicas are reconciling:
   ```bash
   kubectl logs -n kube-policies-system \
     -l app.kubernetes.io/component=policy-manager \
     --tail=30 | grep -E "reconcile|UPSERT|DELETE"
   ```

2. If the Lease is stale (holder pod no longer exists), force re-election by deleting the
   Lease object:
   ```bash
   kubectl delete lease kube-policies-policy-manager \
     -n kube-policies-system
   ```
   A surviving replica acquires the Lease within one election cycle (typically < 30s).

3. Confirm the new Lease holder:
   ```bash
   kubectl get lease kube-policies-policy-manager \
     -n kube-policies-system \
     -o jsonpath='{.spec.holderIdentity}'
   ```

4. Verify audit events resume in the logs of the new leader:
   ```bash
   kubectl logs -n kube-policies-system \
     -l app.kubernetes.io/component=policy-manager \
     --tail=20 | grep auditWhenLeader
   ```

---

## all-replicas-loss

**Scenario:** All admission-webhook and/or policy-manager replicas are down. Fail-closed
means all new admission requests are denied.

1. Check current pod state:
   ```bash
   kubectl get pods -n kube-policies-system
   kubectl describe pods -n kube-policies-system | grep -A5 "Events:"
   ```

2. If pods are in `CrashLoopBackOff` or `ImagePullBackOff`, identify the root cause:
   ```bash
   kubectl logs -n kube-policies-system \
     -l app.kubernetes.io/component=admission-webhook \
     --previous
   ```

3. If the issue is image availability, ensure the image registry is reachable or override
   with a locally mirrored image:
   ```bash
   helm upgrade kube-policies charts/kube-policies \
     --namespace kube-policies-system \
     --reuse-values \
     --set admissionWebhook.image.repository=<mirror-registry>/kube-policies/admission-webhook
   ```

4. If the issue is a configuration error, correct it and roll out:
   ```bash
   helm upgrade kube-policies charts/kube-policies \
     --namespace kube-policies-system \
     --values your-corrected-values.yaml \
     --wait
   ```

5. If cluster operations must continue before KP is recovered, temporarily disable the
   validating webhook (document as a deviation):
   ```bash
   # CAUTION: disabling fail-closed webhook; record as deviation in POA&M
   kubectl annotate validatingwebhookconfiguration kube-policies-webhook \
     kube-policies.io/temporarily-disabled="true" \
     --overwrite
   kubectl patch validatingwebhookconfiguration kube-policies-webhook \
     --type='json' \
     -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]'
   ```
   Re-enable immediately after recovery:
   ```bash
   kubectl patch validatingwebhookconfiguration kube-policies-webhook \
     --type='json' \
     -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Fail"}]'
   ```

6. Verify all replicas are running and ready:
   ```bash
   kubectl rollout status deployment/kube-policies-admission-webhook \
     -n kube-policies-system
   kubectl rollout status deployment/kube-policies-policy-manager \
     -n kube-policies-system
   ```

7. Confirm each new replica has rebuilt its in-memory registry from etcd:
   ```bash
   kubectl logs -n kube-policies-system \
     -l app.kubernetes.io/component=admission-webhook \
     --tail=30 | grep -E "loaded|registry|startup"
   ```

8. Run a smoke test:
   ```bash
   kubectl apply -f test/fixtures/allow-policy-test.yaml --dry-run=server
   ```

---

## References

- Contingency plan: [docs/contingency-plan.md](../contingency-plan.md)
- High availability guide: [docs/high-availability.md](../high-availability.md)
- Backup and restore guide: [docs/backup-restore.md](../backup-restore.md)
- State model: [docs/state-model.md](../state-model.md)
- TLS cert rotation runbook: [docs/runbooks/cert-rotation.md](cert-rotation.md)
- CRD backup CronJob: `charts/kube-policies/templates/backup-cronjob.yaml`
- etcd scripts: `scripts/backup/etcd-snapshot.sh`, `scripts/backup/etcd-restore.sh`
- e2e tests: `test/e2e/state_recovery_test.go`, `test/e2e/backup_restore_test.go`
- NIST SP 800-53 Rev 5: CP-2, CP-9, CP-10; FedRAMP Moderate baseline.
