#!/usr/bin/env bash
# capture.sh — kube-policies demo capture orchestrator.
#
# Per plan §5.3.2 (Iter-3 transactional ordering): stands up a kind cluster,
# deploys kube-policies via the demo Helm values, drives Scenes 3-5 against
# the running cluster, and writes the resulting terminals/audit/screenshots
# into demo/remotion/public/ for the Remotion video build.
#
# This script is intentionally simple — every reusable primitive lives in
# scripts/test/lib.sh (shared with the E2E suites) or demo/capture/lib.sh
# (demo-specific helpers). See demo/capture/AGENTS.md for the contract.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

# Pin the demo cluster name BEFORE sourcing scripts/test/lib.sh (whose default
# is "kube-policies-test"). Per plan OQ-D-4: distinct from kube-policies-test
# to avoid trampling parallel test runs.
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kube-policies-demo}"
export KIND_CLUSTER_NAME

# Worker-1 owns scripts/test/lib.sh. If it isn't present yet during local
# bring-up, the source line below will fail loudly — that's the desired
# behavior; capture.sh cannot run end-to-end without W1's shared helpers.
. "${PROJECT_ROOT}/scripts/test/lib.sh"
. "${SCRIPT_DIR}/lib.sh"

# Plan §5.3.2 + Option-A fix (post-Iter-5 capture-mechanism gap):
# deploy_kube_policies references images at localhost:${REGISTRY_PORT}/...
# and the chart needs cert-manager. test-kind.sh's main() flow runs these
# three prereq steps before deploy; the original capture.sh sketch omitted
# them, leaving the helm install with image-pull and TLS failures.
probe_and_teardown_existing_demo_cluster
create_registry
create_kind_cluster
build_and_push_images
kind_load_demo_images                                  # mirror config doesn't apply; load directly
install_cert_manager
prestage_webhook_cert kube-policies-system             # secret MUST exist before helm --wait checks webhook pod readiness
deploy_kube_policies "${SCRIPT_DIR}/values-demo.yaml"
patch_vwhc_cabundle  kube-policies-system              # VWHC created by helm install above; patch its caBundle
wait_for_deployment

# Scene 3 capture — writes demo/remotion/public/terminals/scene-3-deny.txt
capture_terminals_scene3

# Scene 4 — transactional apply + wait + capture (per Iter-3 I3-4):
# the PolicyException must be Ready before the privileged pod is applied,
# and the audit event with suppressed_by must be observed before we read logs.
apply_and_capture_suppression

# Dashboard + Grafana
capture_dashboard_shots
capture_grafana_shots

write_manifest                  # writes demo/remotion/public/manifest.json
cleanup_kind_cluster
