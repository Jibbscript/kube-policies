#!/usr/bin/env bash
# lib.sh — demo-specific capture helpers.
#
# Sourced by demo/capture/capture.sh after scripts/test/lib.sh (Worker-1).
# All functions here exit on internal error and must be safe to re-source
# (no top-level side effects beyond function definitions and the cleanup
# trap installed by port_forward).
#
# See plan §5.3.3 for the full helper contract and demo/capture/AGENTS.md
# for the named-mask + transactional-capture protocol.

# --- assertion helpers ----------------------------------------------------

# assert_denied_with EXPECTED_MSG <YAML_PATH>
# Applies a manifest and asserts that the apiserver rejected it AND that the
# returned stderr contains EXPECTED_MSG (substring match).
assert_denied_with() {
  local expected_msg="$1"
  local manifest="$2"
  local stderr_file
  stderr_file="$(mktemp)"

  if kubectl apply -f "${manifest}" 2>"${stderr_file}"; then
    rm -f "${stderr_file}"
    echo "ERROR: expected denial but apply succeeded for ${manifest}" >&2
    exit 1
  fi

  if ! grep -q -- "${expected_msg}" "${stderr_file}"; then
    echo "ERROR: stderr did not contain expected denial message" >&2
    echo "  expected: ${expected_msg}" >&2
    echo "  got:" >&2
    sed 's/^/    /' "${stderr_file}" >&2
    rm -f "${stderr_file}"
    exit 1
  fi

  cat "${stderr_file}"
  rm -f "${stderr_file}"
}

# assert_admitted <YAML_PATH>
# Applies a manifest and asserts exit 0.
assert_admitted() {
  local manifest="$1"
  if ! kubectl apply -f "${manifest}"; then
    echo "ERROR: expected admission but apply failed for ${manifest}" >&2
    exit 1
  fi
}

# --- port-forward helpers -------------------------------------------------

# Track active port-forward PIDs so cleanup_pf() can reap them on exit.
_PF_PIDS=()

# port_forward SERVICE LOCAL_PORT REMOTE_PORT [NAMESPACE]
# Starts `kubectl port-forward` in the background and records the PID for
# trap-based cleanup. NAMESPACE defaults to kube-policies-system.
port_forward() {
  local svc="$1" local_port="$2" remote_port="$3"
  local namespace="${4:-kube-policies-system}"

  kubectl port-forward -n "${namespace}" "svc/${svc}" "${local_port}:${remote_port}" >/dev/null 2>&1 &
  local pid=$!
  _PF_PIDS+=("${pid}")

  # Best-effort wait for the local port to be listening.
  local i
  for i in $(seq 1 50); do
    if (echo >"/dev/tcp/127.0.0.1/${local_port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done

  echo "ERROR: port-forward to ${svc}:${remote_port} did not become ready" >&2
  return 1
}

# cleanup_pf — kill any port-forwards started via port_forward.
cleanup_pf() {
  local pid
  for pid in "${_PF_PIDS[@]:-}"; do
    [ -z "${pid}" ] && continue
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  done
  _PF_PIDS=()
}
trap cleanup_pf EXIT

# --- kind cluster lifecycle ----------------------------------------------

# probe_and_teardown_existing_demo_cluster
# Idempotent: if a kind cluster with KIND_CLUSTER_NAME exists, delete it.
probe_and_teardown_existing_demo_cluster() {
  local name="${KIND_CLUSTER_NAME:-kube-policies-demo}"
  if kind get clusters 2>/dev/null | grep -q "^${name}$"; then
    echo "[capture] tearing down existing demo cluster: ${name}"
    kind delete cluster --name "${name}"
  fi
}

# kind_load_demo_images
# scripts/test/lib.sh::create_cluster configures a containerd registry mirror
# from localhost:5001 → http://kind-registry:5000 via containerdConfigPatches,
# but on recent kind versions that patch is silently dropped (no entry appears
# in the running node's /etc/containerd/config.toml). The cluster cannot pull
# from localhost:5001. We side-step the mirror entirely by loading the
# already-pushed images directly into the kind node's containerd store via
# `kind load docker-image`. With imagePullPolicy: IfNotPresent (the chart
# default), kubelet finds the image locally and skips the pull.
kind_load_demo_images() {
  local cluster="${KIND_CLUSTER_NAME:-kube-policies-demo}"
  local port="${REGISTRY_PORT:-5001}"
  for img in admission-webhook policy-manager dashboard; do
    echo "[capture] kind load docker-image localhost:${port}/kube-policies/${img}:test → ${cluster}"
    kind load docker-image "localhost:${port}/kube-policies/${img}:test" --name "${cluster}"
  done
}

# prestage_webhook_cert
# NOTE: legacy belt-and-suspenders post-OQ-2; chart self-bootstraps via templates/admission-webhook-tls.yaml when autoGenerate=true. Kept for resume-after-failure idempotence in the capture flow.
# The chart's webhook deployment mounts a TLS secret named
# `kube-policies-admission-webhook-certs` which the chart does NOT create.
# Generate the secret BEFORE the helm install so `helm --wait` doesn't time
# out waiting on webhook pods stuck in ContainerCreating.
# Requires: kubectl context already pointing at the cluster.
prestage_webhook_cert() {
  local ns="${1:-kube-policies-system}"
  echo "[capture] ensuring namespace ${ns} exists"
  kubectl create namespace "${ns}" --dry-run=client -o yaml | kubectl apply -f -
  echo "[capture] generating webhook TLS cert via scripts/gen-webhook-cert.sh"
  RELEASE_NAME=kube-policies SERVICE_NAME=kube-policies-admission-webhook \
    bash "${PROJECT_ROOT}/scripts/gen-webhook-cert.sh" "${ns}"
}

# patch_vwhc_cabundle
# NOTE: legacy belt-and-suspenders post-OQ-2; chart self-bootstraps via templates/admission-webhook-tls.yaml when autoGenerate=true. Kept for resume-after-failure idempotence in the capture flow.
# The ValidatingWebhookConfiguration's caBundle is empty as rendered (the
# chart expects a cert-manager cainjector annotation, but cert-manager isn't
# creating the Certificate). Patch it from the prestaged secret's ca.crt.
# Run AFTER helm install creates the VWHC.
patch_vwhc_cabundle() {
  local ns="${1:-kube-policies-system}"
  local ca_b64
  ca_b64=$(kubectl get secret kube-policies-admission-webhook-certs -n "${ns}" \
    -o jsonpath='{.data.ca\.crt}')
  if [ -z "${ca_b64}" ]; then
    echo "ERROR: webhook secret has no ca.crt data" >&2
    return 1
  fi
  echo "[capture] patching VWHC caBundle from secret ca.crt"
  kubectl patch validatingwebhookconfiguration kube-policies-validating-webhook \
    --type='json' \
    -p="[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\"value\":\"${ca_b64}\"}]"
}

# create_kind_cluster — defers to scripts/test/lib.sh if it exports
# create_kind_cluster; otherwise minimal local fallback.
if ! declare -F create_kind_cluster >/dev/null 2>&1; then
  create_kind_cluster() {
    local name="${KIND_CLUSTER_NAME:-kube-policies-demo}"
    echo "[capture] creating kind cluster: ${name}"
    kind create cluster --name "${name}"
  }
fi

# cleanup_kind_cluster — symmetric teardown.
if ! declare -F cleanup_kind_cluster >/dev/null 2>&1; then
  cleanup_kind_cluster() {
    local name="${KIND_CLUSTER_NAME:-kube-policies-demo}"
    echo "[capture] deleting kind cluster: ${name}"
    kind delete cluster --name "${name}" || true
  }
fi

# deploy_kube_policies VALUES_YAML
# Wraps the helm install. Delegates to scripts/test/lib.sh if it exports
# deploy_kube_policies; otherwise minimal local fallback.
if ! declare -F deploy_kube_policies >/dev/null 2>&1; then
  deploy_kube_policies() {
    local values="$1"
    kubectl create namespace kube-policies-system --dry-run=client -o yaml | kubectl apply -f -
    kubectl apply -f "${PROJECT_ROOT}/deployments/kubernetes/crds/"
    helm upgrade --install kube-policies "${PROJECT_ROOT}/charts/kube-policies" \
      --namespace kube-policies-system \
      --values "${values}" \
      --wait --timeout=600s
  }
fi

# wait_for_deployment — defer to scripts/test/lib.sh if available.
if ! declare -F wait_for_deployment >/dev/null 2>&1; then
  wait_for_deployment() {
    kubectl wait --for=condition=available --timeout=300s \
      deployment/kube-policies-admission-webhook -n kube-policies-system
    kubectl wait --for=condition=available --timeout=300s \
      deployment/kube-policies-policy-manager -n kube-policies-system
  }
fi

# --- named DOM masks (Principle 4) ---------------------------------------
#
# Both masks are invoked by dashboard.spec.ts via page.evaluate. The shell
# helpers below exist to (a) document the canonical selector + fixed value
# and (b) append the {mask_name, css_selector, fixed_value, applied_at_url}
# tuple to the capture log so reviewers can audit determinism.

# _log_mask MASK_NAME CSS_SELECTOR FIXED_VALUE APPLIED_AT_URL
_log_mask() {
  local pub="${PROJECT_ROOT}/demo/remotion/public"
  local log="${pub}/capture-log.json"
  mkdir -p "${pub}"
  [ -f "${log}" ] || echo "[]" > "${log}"
  local entry
  entry=$(jq -n \
    --arg mask_name     "$1" \
    --arg css_selector  "$2" \
    --arg fixed_value   "$3" \
    --arg applied_at_url "$4" \
    '{mask_name:$mask_name, css_selector:$css_selector, fixed_value:$fixed_value, applied_at_url:$applied_at_url}')
  local tmp
  tmp="$(mktemp)"
  jq --argjson e "${entry}" '. + [$e]' "${log}" > "${tmp}" && mv "${tmp}" "${log}"
}

# mask_relative_time_column APPLIED_AT_URL
# Logs the relative-time mask. Playwright performs the DOM mutation; this is
# the bookkeeping companion.
mask_relative_time_column() {
  local url="${1:-}"
  _log_mask "mask_relative_time_column" 'td[data-col="time"]' "00:00:00" "${url}"
}

# mask_sparkline_path APPLIED_AT_URL
# Per Iter-3 I3-9, fixed ascending polyline:
#   "M0,32 L20,28 L40,22 L60,18 L80,14 L100,10 L120,6"
# Falls back to `svg path:last-of-type` when the data-role attribute is
# missing — the Playwright side handles the selector preference; the shell
# helper records the primary selector for the audit log.
mask_sparkline_path() {
  local url="${1:-}"
  _log_mask "mask_sparkline_path" 'path[data-role="sparkline"]' \
    "M0,32 L20,28 L40,22 L60,18 L80,14 L100,10 L120,6" "${url}"
}

# --- Scene 3 capture ------------------------------------------------------

# capture_terminals_scene3
# Applies the privileged pod fixture, expects denial, captures stderr.
# Per AC-4: asserts the captured text contains
#   "hostPath volumes are not allowed".
capture_terminals_scene3() {
  local pub="${PROJECT_ROOT}/demo/remotion/public"
  local out="${pub}/terminals/scene-3-deny.txt"
  mkdir -p "${pub}/terminals"

  assert_denied_with "hostPath volumes are not allowed" \
    "${SCRIPT_DIR}/fixtures/privileged-pod.yaml" \
    | tee "${out}"

  if ! grep -q "hostPath volumes are not allowed" "${out}"; then
    echo "ERROR: scene-3 capture missing expected denial line" >&2
    exit 1
  fi
}

# --- Scene 4 capture (THE transactional sequence per Iter-4) -------------

apply_and_capture_suppression() {
  local apply_ts
  apply_ts="$(date -u -d '2 seconds ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-2S +%Y-%m-%dT%H:%M:%SZ)"
  local pub="${PROJECT_ROOT}/demo/remotion/public"
  mkdir -p "$pub/terminals" "$pub/audit"

  kubectl apply -f "${SCRIPT_DIR}/fixtures/emergency-exception.yaml" | tee -a "$pub/terminals/scene-4-exception.txt"
  kubectl wait --for=condition=Ready policyexception/emergency-deployment -n default --timeout=5s
  kubectl apply -f "${SCRIPT_DIR}/fixtures/emergency-pod.yaml" | tee -a "$pub/terminals/scene-4-exception.txt"

  _wait_for_audit_event_with_suppressed_by "$apply_ts" 10
  capture_audit_log_for_suppression "$apply_ts" > "$pub/audit/scene-4-audit.json"

  [ -s "$pub/audit/scene-4-audit.json" ] || { echo "ERROR: audit capture empty" >&2; exit 1; }
}

_wait_for_audit_event_with_suppressed_by() {
  local since="$1" deadline="$2" start; start="$(date +%s)"
  while [ "$(( $(date +%s) - start ))" -lt "$deadline" ]; do
    if kubectl logs -n kube-policies-system -l app.kubernetes.io/component=admission-webhook -c admission-webhook --since-time="$since" --prefix=false --tail=200 2>/dev/null \
         | jq -c -e 'select(.suppressed_by and .name=="emergency-pod")' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "ERROR: audit event with suppressed_by not observed within ${deadline}s" >&2
  return 1
}

capture_audit_log_for_suppression() {
  local since="$1"
  kubectl logs -n kube-policies-system -l app.kubernetes.io/component=admission-webhook -c admission-webhook --since-time="$since" --prefix=false --tail=200 \
    | jq -c 'select(.suppressed_by and .name=="emergency-pod")' \
    | head -n 1
}

# --- Dashboard / Grafana captures (Playwright) ---------------------------

# capture_dashboard_shots
# Drives demo/capture/dashboard.spec.ts against the kube-policies dashboard
# SPA. Requires `npx playwright install chromium` to have been run once on
# this host.
_capture_dashboard_shots_cleanup() {
  [ -n "${_CDS_PROXY_PID:-}" ] && kill -TERM "${_CDS_PROXY_PID}" 2>/dev/null || true
  [ -n "${_CDS_PREVIEW_PID:-}" ] && kill -TERM "${_CDS_PREVIEW_PID}" 2>/dev/null || true
  [ -n "${_CDS_PM_PID:-}"   ] && kill -TERM "${_CDS_PM_PID}"   2>/dev/null || true
  sleep 1
  pkill -TERM -f "vite preview" 2>/dev/null || true
  pkill -TERM -f "kubectl port-forward.*kube-policies-policy-manager" 2>/dev/null || true
  pkill -TERM -f "dev_proxy.py" 2>/dev/null || true
  unset _CDS_PROXY_PID _CDS_PREVIEW_PID _CDS_PM_PID
}

capture_dashboard_shots() {
  # Strategy:
  #   The dashboard SPA mounts via Svelte 5's mount() API. Under `vite dev`,
  #   HMR triggers an SSR-check that mis-fires and throws
  #   `lifecycle_function_unavailable: mount(...) is not available on the
  #   server` — the page never renders. Under `vite preview` (static-serve
  #   of the prebuilt bundle) that path is not hit and the SPA renders.
  #
  #   `vite preview` has no built-in proxy, so we run a tiny Python reverse
  #   proxy in front of it that routes /api/* → policy-manager port-forward
  #   and everything else → vite preview. Playwright hits the proxy.
  #
  # Topology:
  #   :8091  ← kubectl port-forward → policy-manager API
  #   :4173  ← vite preview          → web/dist (built SPA)
  #   :8081  ← dev_proxy.py          → /api/* → :8091, else → :4173
  trap _capture_dashboard_shots_cleanup RETURN
  local i

  # NOTE on the build step: we deliberately do NOT run `npm run build` here.
  # The current web/ build emits a Svelte-5 mount() lifecycle error on first
  # render in any browser context (probably an upstream dependency churn —
  # tracked separately, not blocking the demo). The committed web/dist from
  # the last known-good build serves cleanly via vite preview. If web/dist
  # is missing, the user should rebuild manually after fixing the upstream.
  if [ ! -d "${PROJECT_ROOT}/web/dist" ]; then
    echo "ERROR: web/dist not present; run 'cd web && npm run build' first" >&2
    return 1
  fi

  # 1. port-forward policy-manager API → localhost:8091.
  echo "[capture] port-forward policy-manager 8091 → svc/kube-policies-policy-manager:8080"
  kubectl port-forward -n kube-policies-system svc/kube-policies-policy-manager 8091:8080 \
    >/tmp/capture-pm-pf.log 2>&1 &
  _CDS_PM_PID=$!
  for i in $(seq 1 60); do
    if (echo > "/dev/tcp/127.0.0.1/8091") >/dev/null 2>&1; then break; fi
    sleep 0.2
  done

  # 3. start vite preview on :4173 (static-serves web/dist with the working bundle).
  echo "[capture] starting vite preview for web/dist on :4173"
  (
    cd "${PROJECT_ROOT}/web"
    npx vite preview --port 4173 --host 127.0.0.1 \
      >/tmp/capture-preview.log 2>&1
  ) &
  _CDS_PREVIEW_PID=$!
  for i in $(seq 1 60); do
    if curl -fsS -m 2 -o /dev/null http://127.0.0.1:4173/ 2>/dev/null; then break; fi
    sleep 0.5
  done
  if ! curl -fsS -m 2 -o /dev/null http://127.0.0.1:4173/ 2>/dev/null; then
    echo "ERROR: vite preview did not become ready at :4173" >&2
    tail -20 /tmp/capture-preview.log >&2 || true
    return 1
  fi

  # 4. start dev_proxy.py on :8081 (routes /api → :8091, else → :4173).
  echo "[capture] starting dev_proxy.py on :8081"
  python3 "${SCRIPT_DIR}/dev_proxy.py" --port 8081 --spa http://127.0.0.1:4173 \
    --api http://127.0.0.1:8091 > /tmp/capture-proxy.log 2>&1 &
  _CDS_PROXY_PID=$!
  for i in $(seq 1 30); do
    if curl -fsS -m 2 -o /dev/null http://127.0.0.1:8081/ 2>/dev/null; then break; fi
    sleep 0.2
  done
  if ! curl -fsS -m 2 -o /dev/null http://127.0.0.1:8081/ 2>/dev/null; then
    echo "ERROR: dev_proxy did not become ready at :8081" >&2
    tail -20 /tmp/capture-proxy.log >&2 || true
    return 1
  fi

  # 5. SPA-aware wait — give the dashboard a few seconds for first /api fetches
  # so screenshots show populated tiles (not the empty initial render).
  sleep 4

  # 6. run Playwright against the proxy (which serves both SPA + /api/*).
  (
    cd "${PROJECT_ROOT}/demo/capture"
    DASHBOARD_URL="http://localhost:8081" \
      npx playwright test --reporter=line --grep-invert grafana
  )
}

# capture_grafana_shots
# Same harness, pointed at port-forwarded Grafana for the
# kube-policies-overview dashboard panels.
capture_grafana_shots() {
  port_forward "kube-policies-grafana" 3000 80 || return 1
  (
    cd "${PROJECT_ROOT}/demo/remotion"
    GRAFANA_URL="http://localhost:3000" \
      npx playwright test ../../demo/capture/dashboard.spec.ts --grep "grafana"
  )
  cleanup_pf
}

# --- manifest writer ------------------------------------------------------

# write_manifest — walks public/{screenshots,terminals,audit}, sha256s each
# file, emits public/manifest.json. Schema (matches W2's contract):
#   { "version": 1,
#     "generated_at": "<ISO-8601 UTC>",
#     "artifacts": [ { "path": "...", "sha256": "...", "bytes": <int> }, ... ] }
write_manifest() {
  local pub="${PROJECT_ROOT}/demo/remotion/public"
  local manifest="${pub}/manifest.json"
  local generated_at
  generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local entries="[]"
  local f rel sha bytes
  while IFS= read -r f; do
    rel="${f#${pub}/}"
    if command -v sha256sum >/dev/null 2>&1; then
      sha="$(sha256sum "${f}" | awk '{print $1}')"
    else
      sha="$(shasum -a 256 "${f}" | awk '{print $1}')"
    fi
    bytes="$(wc -c < "${f}" | tr -d ' ')"
    entries=$(jq --arg p "${rel}" --arg s "${sha}" --argjson b "${bytes}" \
                 '. + [{path:$p, sha256:$s, bytes:$b}]' <<<"${entries}")
  done < <(find "${pub}/screenshots" "${pub}/terminals" "${pub}/audit" \
              -type f 2>/dev/null | sort)

  jq -n --arg ts "${generated_at}" --argjson a "${entries}" \
    '{version:1, generated_at:$ts, artifacts:$a}' > "${manifest}"
}
