#!/usr/bin/env bash
# etcd-restore.sh — restore an etcd snapshot into a local data directory.
#
# Compliance references
#   NIST SP 800-53 Rev 5  CP-9 (System Backup), CP-10 (System Recovery)
#   CIS Kubernetes Benchmark 1.1.x: 1.1.11 (etcd data dir permissions 0700),
#     1.1.12 (etcd data dir ownership), 2.1 (etcd peer TLS), 2.2 (etcd client TLS)
#
# IMPORTANT: This script targets SELF-MANAGED Kubernetes control planes
# (e.g. kubeadm-bootstrapped clusters).  On managed services (EKS, GKE, AKS)
# the etcd data store is provider-managed and NOT accessible to customers;
# see docs/backup-restore.md § "Managed control planes" for the CRD-level
# backup strategy.
#
# What this script does vs what the operator must do afterwards
# -------------------------------------------------------------
# 1. This script: etcdctl snapshot restore → writes a fresh etcd data dir.
# 2. Operator (manual steps, printed at the end):
#    a. Stop the static etcd Pod (move /etc/kubernetes/manifests/etcd.yaml out).
#    b. Replace the live data dir with the restored one.
#    c. Restore /etc/kubernetes/manifests/etcd.yaml to restart etcd.
#    d. Verify cluster health.
set -euo pipefail

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# ── Defaults ──────────────────────────────────────────────────────────────────
SNAPSHOT_PATH=""
DATA_DIR="/var/lib/etcd-restore"
ETCD_NAME="${ETCD_NAME:-default}"
INITIAL_CLUSTER="${INITIAL_CLUSTER:-default=https://127.0.0.1:2380}"
INITIAL_ADVERTISE_PEER_URLS="${INITIAL_ADVERTISE_PEER_URLS:-https://127.0.0.1:2380}"
INITIAL_CLUSTER_TOKEN="${INITIAL_CLUSTER_TOKEN:-etcd-cluster-1}"
DRY_RUN=false

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} --snapshot <path> [OPTIONS]

Restore an etcd snapshot into a local data directory.

Required:
  --snapshot PATH          snapshot file to restore from (env: SNAPSHOT_PATH)

Options:
  --data-dir PATH          target restore directory
                           default: /var/lib/etcd-restore
  --name NAME              etcd member name (env: ETCD_NAME)
                           default: default
  --initial-cluster STR    initial cluster (env: INITIAL_CLUSTER)
                           default: default=https://127.0.0.1:2380
  --initial-advertise-peer-urls URL
                           (env: INITIAL_ADVERTISE_PEER_URLS)
                           default: https://127.0.0.1:2380
  --initial-cluster-token TOK
                           (env: INITIAL_CLUSTER_TOKEN)
                           default: etcd-cluster-1
  --dry-run                print the etcdctl command(s) without executing them
  -h, --help               show this help and exit 0

Environment variables are read first; flags override them.
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot)
      [[ $# -ge 2 ]] || die "--snapshot requires an argument"
      SNAPSHOT_PATH="$2"; shift 2 ;;
    --data-dir)
      [[ $# -ge 2 ]] || die "--data-dir requires an argument"
      DATA_DIR="$2"; shift 2 ;;
    --name)
      [[ $# -ge 2 ]] || die "--name requires an argument"
      ETCD_NAME="$2"; shift 2 ;;
    --initial-cluster)
      [[ $# -ge 2 ]] || die "--initial-cluster requires an argument"
      INITIAL_CLUSTER="$2"; shift 2 ;;
    --initial-advertise-peer-urls)
      [[ $# -ge 2 ]] || die "--initial-advertise-peer-urls requires an argument"
      INITIAL_ADVERTISE_PEER_URLS="$2"; shift 2 ;;
    --initial-cluster-token)
      [[ $# -ge 2 ]] || die "--initial-cluster-token requires an argument"
      INITIAL_CLUSTER_TOKEN="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=true; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "Unknown argument: $1 (run with --help for usage)" ;;
  esac
done

# ── Prerequisite checks ───────────────────────────────────────────────────────
[[ -n "${SNAPSHOT_PATH}" ]] || \
  die "Snapshot path is required. Use --snapshot <path> or set SNAPSHOT_PATH."

if [[ "${DRY_RUN}" == false ]]; then
  command -v etcdctl >/dev/null 2>&1 || \
    die "etcdctl not found in PATH. Install etcd client tools and retry."
  [[ -f "${SNAPSHOT_PATH}" ]] || die "Snapshot file not found: ${SNAPSHOT_PATH}"
  [[ ! -e "${DATA_DIR}" ]] || \
    die "Target data dir already exists: ${DATA_DIR}. Remove it first to avoid corruption."
fi

# ── Build the restore command ─────────────────────────────────────────────────
RESTORE_CMD=(
  env ETCDCTL_API=3
  etcdctl snapshot restore "${SNAPSHOT_PATH}"
  --data-dir="${DATA_DIR}"
  --name="${ETCD_NAME}"
  --initial-cluster="${INITIAL_CLUSTER}"
  --initial-cluster-token="${INITIAL_CLUSTER_TOKEN}"
  --initial-advertise-peer-urls="${INITIAL_ADVERTISE_PEER_URLS}"
)

# ── Execute or dry-run ────────────────────────────────────────────────────────
if [[ "${DRY_RUN}" == true ]]; then
  echo "[dry-run] Would execute:"
  echo "  ${RESTORE_CMD[*]}"
  exit 0
fi

echo "==> Restoring etcd snapshot: ${SNAPSHOT_PATH}"
echo "    Target data dir: ${DATA_DIR}"
"${RESTORE_CMD[@]}"

echo ""
echo "==> Setting restrictive permissions on restored data directory (CIS 1.1.11/1.1.12):"
chmod 0700 "${DATA_DIR}"
echo "    chmod 0700 ${DATA_DIR} — done"
echo "    NOTE: ensure ownership is set to the etcd user (e.g. chown -R etcd:etcd ${DATA_DIR})"

echo ""
echo "======================================================================"
echo "  MANUAL STEPS REQUIRED TO COMPLETE CONTROL-PLANE RECOVERY"
echo "======================================================================"
echo ""
echo "  The data directory has been restored to: ${DATA_DIR}"
echo "  You must now perform the following steps as root on the control-plane"
echo "  node before etcd will serve the restored state:"
echo ""
echo "  1. Stop the static etcd Pod by moving its manifest out:"
echo "       mv /etc/kubernetes/manifests/etcd.yaml /tmp/etcd.yaml"
echo "       # Wait until: crictl ps | grep etcd  (no running etcd container)"
echo ""
echo "  2. Back up the live etcd data directory:"
echo "       mv /var/lib/etcd /var/lib/etcd.bak"
echo ""
echo "  3. Move the restored data directory into place:"
echo "       mv ${DATA_DIR} /var/lib/etcd"
echo "       chown -R root:root /var/lib/etcd   # adjust to your etcd user"
echo ""
echo "  4. Restart etcd by restoring the manifest:"
echo "       mv /tmp/etcd.yaml /etc/kubernetes/manifests/etcd.yaml"
echo ""
echo "  5. Verify cluster health:"
echo "       ETCDCTL_API=3 etcdctl endpoint health \\"
echo "         --endpoints=https://127.0.0.1:2379 \\"
echo "         --cacert=/etc/kubernetes/pki/etcd/ca.crt \\"
echo "         --cert=/etc/kubernetes/pki/etcd/server.crt \\"
echo "         --key=/etc/kubernetes/pki/etcd/server.key"
echo "       kubectl get nodes"
echo ""
echo "  6. For multi-node control planes: repeat steps 1–5 on each etcd member,"
echo "     adjusting --name, --initial-cluster, and --initial-advertise-peer-urls"
echo "     per member. All members must be restored from the SAME snapshot."
echo ""
echo "======================================================================"
