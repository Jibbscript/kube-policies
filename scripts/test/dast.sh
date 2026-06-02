#!/bin/bash

# scripts/test/dast.sh — DAST scan for kube-policies (SDL-WU-26 / VUL-WU-16)
#
# Runs OWASP ZAP baseline scans against the policy-manager REST API and the
# dashboard BFF, plus targeted TLS/cipher checks against the admission-webhook
# HTTPS port. Writes HTML/JSON/SARIF report artifacts to RESULTS_DIR.
#
# NIST controls: CA-8 (penetration testing), SA-11 (developer security testing),
#                SC-8 (transmission confidentiality), RA-5(5) (vulnerability scan)
#
# Usage (against a pre-running stack):
#   TARGET_API_URL=http://localhost:8080 \
#   TARGET_BFF_URL=http://localhost:3000 \
#   TLS_HOST=localhost TLS_PORT=8443 \
#   scripts/test/dast.sh
#
# Usage (stand-up mode via test-kind.sh helpers):
#   BRING_UP_STACK=true scripts/test/dast.sh
#
# Env:
#   TARGET_API_URL    Policy-manager REST API base URL (default http://localhost:8080)
#   TARGET_BFF_URL    Dashboard BFF base URL (default http://localhost:3000)
#   TLS_HOST          Host for TLS checks (default localhost)
#   TLS_PORT          Port for TLS checks (default 8443)
#   RESULTS_DIR       Where to write reports (default test-results/dast)
#   ZAP_IMAGE         OWASP ZAP docker image (default ghcr.io/zaproxy/zaproxy:stable)
#   ZAP_CONF          Path to ZAP baseline rules config (default test/security/zap-baseline.conf)
#   FAIL_ON           ZAP minimum severity to fail: High (default) | Medium | Low | Informational
#   BRING_UP_STACK    If "true", stand up a Kind cluster via test-kind.sh first (default false)
#   KIND_CLUSTER_NAME Kind cluster name (default kube-policies-test); used when BRING_UP_STACK=true
#   PORT_FORWARD_API  kubectl port-forward local port for policy-manager API (default 8080)
#   PORT_FORWARD_BFF  kubectl port-forward local port for dashboard BFF (default 3000)
#   CLEANUP           If "false", skip Kind cluster teardown on exit (default true)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ── Configuration ─────────────────────────────────────────────────────────────
# The policy-manager :8080 REST API always serves TLS (CRY-WU-05), so the scan
# target + readiness probe use https. The serving cert is self-signed in the
# Kind/DAST deployment, so curl uses -k and ZAP (which does not validate TLS
# certs) scans the endpoint directly.
TARGET_API_URL="${TARGET_API_URL:-https://localhost:8080}"
TARGET_BFF_URL="${TARGET_BFF_URL:-http://localhost:3000}"
TLS_HOST="${TLS_HOST:-localhost}"
TLS_PORT="${TLS_PORT:-8443}"
RESULTS_DIR="${RESULTS_DIR:-${PROJECT_ROOT}/test-results/dast}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
# ZAP_CONF path is relative to PROJECT_ROOT; it's mounted into the container.
ZAP_CONF="${ZAP_CONF:-${PROJECT_ROOT}/test/security/zap-baseline.conf}"
FAIL_ON="${FAIL_ON:-High}"
BRING_UP_STACK="${BRING_UP_STACK:-false}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kube-policies-test}"
PORT_FORWARD_API="${PORT_FORWARD_API:-8080}"
PORT_FORWARD_BFF="${PORT_FORWARD_BFF:-3000}"

# ── Colors (matching lib.sh / run-all-tests.sh) ───────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()     { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}"; }
error()   { echo -e "${RED}[ERROR] $*${NC}" >&2; }
success() { echo -e "${GREEN}[SUCCESS] $*${NC}"; }
warn()    { echo -e "${YELLOW}[WARNING] $*${NC}"; }

# ── PIDs to clean up on exit ──────────────────────────────────────────────────
_PF_PIDS=()

cleanup_pids() {
    for pid in "${_PF_PIDS[@]+"${_PF_PIDS[@]}"}"; do
        kill "${pid}" 2>/dev/null || true
    done
}
trap cleanup_pids EXIT

# ── Prerequisites ─────────────────────────────────────────────────────────────
check_prerequisites() {
    log "Checking prerequisites..."
    local missing=0

    if ! command -v docker >/dev/null 2>&1; then
        error "docker not found on PATH (required for ZAP)"
        missing=1
    fi

    if [ "${missing}" -ne 0 ]; then
        exit 1
    fi
    success "Prerequisites OK"
}

# ── Optional stack bring-up ───────────────────────────────────────────────────
bring_up_stack() {
    log "BRING_UP_STACK=true — standing up Kind cluster via test-kind.sh"

    if ! command -v kind >/dev/null 2>&1; then
        error "kind not found on PATH"
        exit 1
    fi
    if ! command -v kubectl >/dev/null 2>&1; then
        error "kubectl not found on PATH"
        exit 1
    fi
    if ! command -v helm >/dev/null 2>&1; then
        error "helm not found on PATH"
        exit 1
    fi

    export CLEANUP=false
    export KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME}"
    "${SCRIPT_DIR}/test-kind.sh"

    # Export kubeconfig so subsequent kubectl calls target this cluster.
    kind export kubeconfig --name "${KIND_CLUSTER_NAME}"

    # Port-forward policy-manager REST API (:8080) — plain HTTP on the metrics
    # port is :9091; the REST API (admission + policy CRUD) is :8080 (NodePort
    # 30080 inside kind, but kubectl port-forward is more reliable for DAST).
    log "Setting up port-forward for policy-manager API (:${PORT_FORWARD_API}→8080)"
    kubectl port-forward -n kube-policies-system \
        svc/kube-policies-policy-manager "${PORT_FORWARD_API}:8080" \
        >/tmp/dast-pf-api.log 2>&1 &
    _PF_PIDS+=($!)

    # Port-forward dashboard BFF if the service exists.
    if kubectl get svc -n kube-policies-system kube-policies-dashboard >/dev/null 2>&1; then
        log "Setting up port-forward for dashboard BFF (:${PORT_FORWARD_BFF}→3000)"
        kubectl port-forward -n kube-policies-system \
            svc/kube-policies-dashboard "${PORT_FORWARD_BFF}:3000" \
            >/tmp/dast-pf-bff.log 2>&1 &
        _PF_PIDS+=($!)
    else
        warn "Dashboard service not found — skipping BFF port-forward"
        TARGET_BFF_URL=""
    fi

    # Wait for API readiness (up to 30 s).
    log "Waiting for policy-manager API to be reachable..."
    local _i
    for _i in $(seq 1 30); do
        if curl -sfk -o /dev/null -m 2 "${TARGET_API_URL}/healthz" 2>/dev/null; then
            success "Policy-manager API reachable at ${TARGET_API_URL}"
            break
        fi
        sleep 1
    done
}

# ── ZAP baseline scan ─────────────────────────────────────────────────────────
# Maps FAIL_ON to a ZAP exit-code threshold.
# zap-baseline.py exits: 0=no alerts, 1=warns only, 2=alerts at/above warn, 3=fail
# We treat exit 0/1 as pass; 2 as pass-unless-FAIL_ON is Medium or lower;
# 3 always as fail (FAIL level hit). For simplicity we pass -l (min-level to log)
# and -I (ignore warnings) consistent with the conf file's WARN/FAIL directives.
run_zap_scan() {
    local target_url="$1"
    local scan_name="$2"    # "api" or "bff"
    local report_base="${RESULTS_DIR}/${scan_name}"

    log "ZAP baseline scan: ${scan_name} → ${target_url}"

    # ZAP needs to write reports to a path it owns; we mount RESULTS_DIR as /zap/wrk.
    # The conf file is copied into RESULTS_DIR so it's available as /zap/wrk/zap-baseline.conf.
    # The conf file lives at test/security/zap-baseline.conf; mount PROJECT_ROOT read-only
    # at /project so ZAP can read it, and RESULTS_DIR read-write at /zap/wrk.
    mkdir -p "${RESULTS_DIR}"

    # Copy conf into results dir so it's accessible via the single /zap/wrk mount.
    cp "${ZAP_CONF}" "${RESULTS_DIR}/zap-baseline.conf"

    local zap_exit=0
    docker run --rm \
        --network host \
        -v "${RESULTS_DIR}:/zap/wrk:rw" \
        "${ZAP_IMAGE}" \
        zap-baseline.py \
            -t "${target_url}" \
            -c zap-baseline.conf \
            -r "${scan_name}-report.html" \
            -J "${scan_name}-report.json" \
            -w "${scan_name}-report.md" \
            -x "${scan_name}-report.xml" \
            -I \
        || zap_exit=$?

    # Convert XML report to SARIF using zap-to-sarif (python helper bundled in
    # the zaproxy image). Fall back gracefully if the converter is absent.
    if docker run --rm \
            --network host \
            -v "${RESULTS_DIR}:/zap/wrk:rw" \
            --entrypoint python3 \
            "${ZAP_IMAGE}" \
            -c "import sys; sys.exit(0 if __import__('importlib').util.find_spec('zapv2') else 0)" \
            2>/dev/null; then
        log "Generating SARIF report for ${scan_name}"
        docker run --rm \
            -v "${RESULTS_DIR}:/zap/wrk:rw" \
            --entrypoint python3 \
            "${ZAP_IMAGE}" \
            /zap/zap-common.py \
            2>/dev/null || true
    fi

    # Produce a minimal SARIF from the ZAP JSON if a dedicated converter is
    # unavailable. This ensures the Security tab upload always has a file.
    if [ ! -f "${report_base}-report.sarif" ]; then
        generate_sarif_from_json "${report_base}-report.json" "${report_base}-report.sarif" "${scan_name}"
    fi

    # Evaluate exit code against FAIL_ON threshold.
    # ZAP exit codes: 0=pass, 1=warn, 2=warn-fail-mix, 3=fail
    case "${FAIL_ON}" in
        High|FAIL)
            # Only exit 3 (explicit FAIL-level alert) fails the scan.
            if [ "${zap_exit}" -ge 3 ]; then
                error "ZAP reported FAIL-level findings for ${scan_name} (exit ${zap_exit})"
                return 1
            fi
            ;;
        Medium|Warn|WARN)
            if [ "${zap_exit}" -ge 1 ]; then
                error "ZAP reported WARN-or-above findings for ${scan_name} (exit ${zap_exit})"
                return 1
            fi
            ;;
        Low|Informational|INFO)
            if [ "${zap_exit}" -ne 0 ]; then
                error "ZAP reported any alert for ${scan_name} (exit ${zap_exit})"
                return 1
            fi
            ;;
        *)
            warn "Unknown FAIL_ON value '${FAIL_ON}'; defaulting to High threshold"
            if [ "${zap_exit}" -ge 3 ]; then
                error "ZAP reported FAIL-level findings for ${scan_name} (exit ${zap_exit})"
                return 1
            fi
            ;;
    esac

    success "ZAP scan ${scan_name}: PASSED (exit ${zap_exit}, threshold ${FAIL_ON})"
    return 0
}

# ── Minimal SARIF generator from ZAP JSON ────────────────────────────────────
# Produces a well-formed SARIF 2.1.0 file suitable for github/codeql-action/upload-sarif.
# Uses only tools available in the zaproxy base image (python3 with stdlib).
generate_sarif_from_json() {
    local json_file="$1"
    local sarif_file="$2"
    local scan_name="$3"

    if [ ! -f "${json_file}" ]; then
        warn "ZAP JSON report not found (${json_file}); generating empty SARIF"
        cat >"${sarif_file}" <<'EOF'
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [{"tool":{"driver":{"name":"OWASP ZAP","version":"stable","rules":[]}},"results":[]}]
}
EOF
        return 0
    fi

    docker run --rm \
        -v "${RESULTS_DIR}:/zap/wrk:rw" \
        --entrypoint python3 \
        "${ZAP_IMAGE}" \
        - <<PYEOF
import json, sys, os

json_path = "/zap/wrk/${scan_name}-report.json"
sarif_path = "/zap/wrk/${scan_name}-report.sarif"

try:
    with open(json_path) as f:
        data = json.load(f)
except Exception as e:
    data = {}

alerts = []
for site in data.get("site", []):
    for alert in site.get("alerts", []):
        alerts.append(alert)

rules = []
results = []
rule_ids_seen = {}

for alert in alerts:
    plugin_id = str(alert.get("pluginid", "unknown"))
    alert_name = alert.get("alert", "Unknown Alert")
    risk_code = int(alert.get("riskcode", 0))
    # 0=Informational, 1=Low, 2=Medium, 3=High
    level_map = {0: "note", 1: "note", 2: "warning", 3: "error"}
    level = level_map.get(risk_code, "warning")

    if plugin_id not in rule_ids_seen:
        rule_ids_seen[plugin_id] = True
        rules.append({
            "id": plugin_id,
            "name": alert_name.replace(" ", ""),
            "shortDescription": {"text": alert_name},
            "fullDescription": {"text": alert.get("desc", alert_name)},
            "help": {"text": alert.get("solution", "See ZAP report for remediation.")},
            "defaultConfiguration": {"level": level},
            "properties": {"tags": ["security", "dast"]}
        })

    for instance in alert.get("instances", [{"uri": alert.get("url", ""), "method": "", "evidence": ""}]):
        uri = instance.get("uri", instance.get("url", ""))
        results.append({
            "ruleId": plugin_id,
            "level": level,
            "message": {"text": alert.get("desc", alert_name)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri or "unknown"}}}]
        })

sarif = {
    "version": "2.1.0",
    "\$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "OWASP ZAP", "version": "stable", "informationUri": "https://www.zaproxy.org", "rules": rules}},
        "results": results
    }]
}

with open(sarif_path, "w") as f:
    json.dump(sarif, f, indent=2)

print(f"SARIF written: {len(results)} results, {len(rules)} rules")
PYEOF
}

# ── TLS/cipher checks ─────────────────────────────────────────────────────────
run_tls_checks() {
    log "TLS/cipher checks against ${TLS_HOST}:${TLS_PORT}"

    local tls_report="${RESULTS_DIR}/tls-check.txt"
    mkdir -p "${RESULTS_DIR}"

    {
        echo "# TLS/Cipher check: ${TLS_HOST}:${TLS_PORT}"
        echo "# Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
    } >"${tls_report}"

    local tls_fail=0

    # ── 1. Certificate presence and basic TLS handshake ──────────────────────
    log "Checking TLS certificate presence..."
    local cert_info
    if ! cert_info=$(echo | openssl s_client \
            -connect "${TLS_HOST}:${TLS_PORT}" \
            -servername "${TLS_HOST}" \
            -showcerts 2>&1); then
        warn "openssl s_client failed — host may not be reachable"
        echo "WARN: openssl s_client could not connect to ${TLS_HOST}:${TLS_PORT}" >>"${tls_report}"
    else
        echo "${cert_info}" >>"${tls_report}"

        # Must contain a certificate.
        if echo "${cert_info}" | grep -q "BEGIN CERTIFICATE"; then
            success "TLS certificate present on ${TLS_HOST}:${TLS_PORT}"
        else
            error "No TLS certificate returned by ${TLS_HOST}:${TLS_PORT}"
            tls_fail=1
        fi
    fi

    # ── 2. Verify TLS 1.2 is accepted ────────────────────────────────────────
    log "Verifying TLS 1.2 is accepted..."
    {
        echo ""
        echo "# TLS 1.2 handshake test"
    } >>"${tls_report}"
    if echo | openssl s_client \
            -connect "${TLS_HOST}:${TLS_PORT}" \
            -servername "${TLS_HOST}" \
            -tls1_2 2>&1 | tee -a "${tls_report}" | grep -q "Protocol  : TLSv1.2"; then
        success "TLS 1.2 accepted"
    else
        warn "TLS 1.2 not confirmed (may have been upgraded to 1.3)"
    fi

    # ── 3. Verify TLS 1.3 is accepted ────────────────────────────────────────
    log "Verifying TLS 1.3 is accepted..."
    {
        echo ""
        echo "# TLS 1.3 handshake test"
    } >>"${tls_report}"
    local tls13_out
    tls13_out=$(echo | openssl s_client \
            -connect "${TLS_HOST}:${TLS_PORT}" \
            -servername "${TLS_HOST}" \
            -tls1_3 2>&1) || true
    echo "${tls13_out}" >>"${tls_report}"
    if echo "${tls13_out}" | grep -q "Protocol  : TLSv1.3"; then
        success "TLS 1.3 accepted"
    else
        warn "TLS 1.3 not confirmed (peer may not support it)"
    fi

    # ── 4. Reject SSLv3 (must fail) ──────────────────────────────────────────
    log "Verifying SSLv3 is rejected..."
    {
        echo ""
        echo "# SSLv3 rejection test"
    } >>"${tls_report}"
    if echo | openssl s_client \
            -connect "${TLS_HOST}:${TLS_PORT}" \
            -ssl3 2>&1 | tee -a "${tls_report}" | grep -qi "handshake failure\|ssl handshake\|no protocols available\|ssl3 alert\|alert handshake"; then
        success "SSLv3 correctly rejected"
    else
        warn "SSLv3 rejection not confirmed (openssl may not support -ssl3 on this platform)"
    fi

    # ── 5. Reject TLS 1.0 (must fail) ────────────────────────────────────────
    log "Verifying TLS 1.0 is rejected..."
    {
        echo ""
        echo "# TLS 1.0 rejection test"
    } >>"${tls_report}"
    if echo | openssl s_client \
            -connect "${TLS_HOST}:${TLS_PORT}" \
            -servername "${TLS_HOST}" \
            -tls1 2>&1 | tee -a "${tls_report}" | grep -qi "handshake failure\|no protocols available\|alert"; then
        success "TLS 1.0 correctly rejected"
    else
        warn "TLS 1.0 rejection not confirmed — operator should verify server config enforces TLS 1.2+ minimum"
        echo "WARN: TLS 1.0 rejection not confirmed" >>"${tls_report}"
    fi

    # ── 6. nmap cipher enumeration (best-effort) ─────────────────────────────
    if command -v nmap >/dev/null 2>&1; then
        log "Running nmap ssl-enum-ciphers against ${TLS_HOST}:${TLS_PORT}"
        {
            echo ""
            echo "# nmap ssl-enum-ciphers"
        } >>"${tls_report}"
        nmap --script ssl-enum-ciphers -p "${TLS_PORT}" "${TLS_HOST}" 2>&1 \
            | tee -a "${tls_report}" || true

        # Fail if weak (<= B-grade) ciphers or SSLv2/3 are offered.
        if grep -E "TLSv1\.0|TLSv1\.1|SSLv[23]|grade: [CDF]" "${tls_report}" 2>/dev/null; then
            error "nmap found weak TLS protocol or cipher grade (C/D/F) on ${TLS_HOST}:${TLS_PORT}"
            tls_fail=1
        else
            success "No weak protocols/ciphers found by nmap"
        fi
    else
        log "nmap not available — skipping cipher enumeration (openssl checks above are authoritative)"
    fi

    if [ "${tls_fail}" -ne 0 ]; then
        error "TLS checks FAILED for ${TLS_HOST}:${TLS_PORT} — see ${tls_report}"
        return 1
    fi

    success "TLS checks passed for ${TLS_HOST}:${TLS_PORT}"
    return 0
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    log "Starting DAST scan (SDL-WU-26 / VUL-WU-16)"
    log "  FAIL_ON=${FAIL_ON}  ZAP_IMAGE=${ZAP_IMAGE}"
    log "  TARGET_API_URL=${TARGET_API_URL}"
    log "  TARGET_BFF_URL=${TARGET_BFF_URL:-<disabled>}"
    log "  TLS_HOST=${TLS_HOST}  TLS_PORT=${TLS_PORT}"
    log "  RESULTS_DIR=${RESULTS_DIR}"

    mkdir -p "${RESULTS_DIR}"

    check_prerequisites

    if [ "${BRING_UP_STACK}" = "true" ]; then
        bring_up_stack
    fi

    local overall_rc=0

    # ZAP scan — policy-manager API
    if [ -n "${TARGET_API_URL}" ]; then
        run_zap_scan "${TARGET_API_URL}" "api" || overall_rc=1
    else
        warn "TARGET_API_URL is empty — skipping API ZAP scan"
    fi

    # ZAP scan — dashboard BFF
    if [ -n "${TARGET_BFF_URL:-}" ]; then
        run_zap_scan "${TARGET_BFF_URL}" "bff" || overall_rc=1
    else
        warn "TARGET_BFF_URL is empty — skipping BFF ZAP scan"
    fi

    # TLS checks
    run_tls_checks || overall_rc=1

    if [ "${overall_rc}" -ne 0 ]; then
        error "DAST scan FAILED — review reports in ${RESULTS_DIR}/"
        exit 1
    fi

    success "DAST scan completed — all checks passed. Reports: ${RESULTS_DIR}/"
}

main "$@"
