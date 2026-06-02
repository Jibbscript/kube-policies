#!/usr/bin/env bash
# helm-deps.sh — resolve chart subchart dependencies before any
# `helm template` / `helm unittest` / `helm install` of charts/kube-policies.
#
# charts/kube-policies declares the prometheus + grafana subcharts as
# dependencies, but the resolved .tgz under charts/kube-policies/charts/ are
# gitignored. So CI runners (and fresh local clones) must rebuild them from
# Chart.lock. `helm dependency build` requires the upstream repos to be
# registered first, hence the `helm repo add` calls (idempotent via
# --force-update). CWD-independent: resolves the chart relative to this script.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART_DIR="${1:-${ROOT_DIR}/charts/kube-policies}"

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update >/dev/null
helm repo add grafana https://grafana.github.io/helm-charts --force-update >/dev/null
helm dependency build "${CHART_DIR}"
