#!/usr/bin/env bash
# etcd-snapshot.sh — take an etcdctl snapshot save of the etcd datastore.
#
# Compliance references
#   NIST SP 800-53 Rev 5  CP-9 (System Backup)
#   CIS Kubernetes Benchmark 1.1.x: 1.1.11 (etcd data dir permissions 0700),
#     1.1.12 (etcd data dir ownership), 2.1 (etcd peer TLS), 2.2 (etcd client TLS)
#
# IMPORTANT: This script targets SELF-MANAGED Kubernetes control planes
# (e.g. kubeadm-bootstrapped clusters).  On managed services (EKS, GKE, AKS)
# the etcd data store is provider-managed and NOT accessible to customers;
# see docs/backup-restore.md § "Managed control planes" for the CRD-level
# backup strategy.
set -euo pipefail

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# ── Defaults ──────────────────────────────────────────────────────────────────
ETCDCTL_ENDPOINTS="${ETCDCTL_ENDPOINTS:-https://127.0.0.1:2379}"
ETCD_CACERT="${ETCD_CACERT:-/etc/kubernetes/pki/etcd/ca.crt}"
ETCD_CERT="${ETCD_CERT:-/etc/kubernetes/pki/etcd/server.crt}"
ETCD_KEY="${ETCD_KEY:-/etc/kubernetes/pki/etcd/server.key}"
# Snapshot output path. Build default from UTC timestamp without relying on
# a subshell variable that might be unset under set -u.
_TS="$(date -u '+%Y%m%dT%H%M%SZ')"
SNAPSHOT_PATH="${SNAPSHOT_PATH:-./etcd-snapshot-${_TS}.db}"
DRY_RUN=false

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Take an etcdctl snapshot save of the etcd datastore.

Options:
  --endpoints ENDPOINTS   etcd endpoints (env: ETCDCTL_ENDPOINTS)
                          default: https://127.0.0.1:2379
  --cacert PATH           CA certificate (env: ETCD_CACERT)
                          default: /etc/kubernetes/pki/etcd/ca.crt
  --cert PATH             client certificate (env: ETCD_CERT)
                          default: /etc/kubernetes/pki/etcd/server.crt
  --key PATH              client key (env: ETCD_KEY)
                          default: /etc/kubernetes/pki/etcd/server.key
  --out PATH              output snapshot file (env: SNAPSHOT_PATH)
                          default: ./etcd-snapshot-<UTC-timestamp>.db
  --dry-run               print the etcdctl command(s) without executing them
  -h, --help              show this help and exit 0

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
    --endpoints)
      [[ $# -ge 2 ]] || die "--endpoints requires an argument"
      ETCDCTL_ENDPOINTS="$2"; shift 2 ;;
    --cacert)
      [[ $# -ge 2 ]] || die "--cacert requires an argument"
      ETCD_CACERT="$2"; shift 2 ;;
    --cert)
      [[ $# -ge 2 ]] || die "--cert requires an argument"
      ETCD_CERT="$2"; shift 2 ;;
    --key)
      [[ $# -ge 2 ]] || die "--key requires an argument"
      ETCD_KEY="$2"; shift 2 ;;
    --out)
      [[ $# -ge 2 ]] || die "--out requires an argument"
      SNAPSHOT_PATH="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=true; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "Unknown argument: $1 (run with --help for usage)" ;;
  esac
done

# ── Prerequisite checks ───────────────────────────────────────────────────────
[[ -n "${ETCD_CACERT}" ]] || die "CA cert path is empty; set --cacert or ETCD_CACERT."
[[ -n "${ETCD_CERT}"   ]] || die "Client cert path is empty; set --cert or ETCD_CERT."
[[ -n "${ETCD_KEY}"    ]] || die "Client key path is empty; set --key or ETCD_KEY."

if [[ "${DRY_RUN}" == false ]]; then
  command -v etcdctl >/dev/null 2>&1 || \
    die "etcdctl not found in PATH. Install etcd client tools and retry."
  [[ -f "${ETCD_CACERT}" ]] || die "CA cert not found: ${ETCD_CACERT}"
  [[ -f "${ETCD_CERT}"   ]] || die "Client cert not found: ${ETCD_CERT}"
  [[ -f "${ETCD_KEY}"    ]] || die "Client key not found: ${ETCD_KEY}"
fi

# ── Build the save command ────────────────────────────────────────────────────
SAVE_CMD=(
  env ETCDCTL_API=3
  etcdctl snapshot save "${SNAPSHOT_PATH}"
  --endpoints="${ETCDCTL_ENDPOINTS}"
  --cacert="${ETCD_CACERT}"
  --cert="${ETCD_CERT}"
  --key="${ETCD_KEY}"
)

STATUS_CMD=(
  env ETCDCTL_API=3
  etcdctl snapshot status "${SNAPSHOT_PATH}"
  --write-out=table
)

# ── Execute or dry-run ────────────────────────────────────────────────────────
if [[ "${DRY_RUN}" == true ]]; then
  echo "[dry-run] Would execute:"
  echo "  ${SAVE_CMD[*]}"
  echo ""
  echo "[dry-run] Then verify with:"
  echo "  ${STATUS_CMD[*]}"
  exit 0
fi

echo "==> Taking etcd snapshot: ${SNAPSHOT_PATH}"
"${SAVE_CMD[@]}"

echo ""
echo "==> Verifying snapshot integrity:"
"${STATUS_CMD[@]}"

echo ""
echo "==> Snapshot saved successfully: ${SNAPSHOT_PATH}"
echo "    Secure the file: chmod 0600 \"${SNAPSHOT_PATH}\""
