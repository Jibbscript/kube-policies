# demo/capture — AGENTS.md

Capture pipeline for the kube-policies demo video. The Bash + Playwright code
here is the *only* path that talks to a live kind cluster — Remotion (`../remotion/`)
consumes the artifacts written to `../remotion/public/` and never touches the
cluster itself.

## Files

| File | Purpose |
| --- | --- |
| `capture.sh` | Top-level orchestrator (plan §5.3.2 Iter-3 transactional ordering). |
| `lib.sh` | All demo-specific helpers (port-forwards, masks, scene captures, manifest). |
| `dashboard.spec.ts` | Playwright spec for dashboard + Grafana screenshots. |
| `values-demo.yaml` | Helm values override; CRITICAL: `audit.backend.type=stdout`, `flushInterval=1s`. |
| `fixtures/` | Five YAML inputs; see fixture set below. |

`capture.sh` sources `scripts/test/lib.sh` (owned by Worker-1, shared with the
E2E suites) before `demo/capture/lib.sh`, so any helper Worker-1 exports
overrides our local fallback definitions.

## Fixture set

| Fixture | Scene | Role |
| --- | --- | --- |
| `security-baseline.yaml` | bootstrap | Byte-identical copy of `examples/policies/security-baseline.yaml`. AC-16 diff-lint enforces drift = 0. |
| `privileged-pod.yaml` | Scene 3 | Privileged Pod; expected to be **denied** with `Container must not run in privileged mode` (AC-4). |
| `emergency-exception.yaml` | Scene 4 | PolicyException CR scoped to Pods in `default` covering `no-privileged-containers`. Authored against the current CRD schema in `internal/policymanager/apis/policies/v1/types.go` (snake_case JSON tags, `scope.namespaces`/`scope.resources`). |
| `emergency-pod.yaml` | Scene 4 | Privileged Pod named `emergency-pod`; expected to be **admitted via suppression**, with the admission-webhook emitting `{suppressed_by, name:"emergency-pod"}`. |
| `compliant-pod.yaml` | Scene 5 montage | Passes every rule (runAsNonRoot, explicit non-:latest tag, no privileged, no hostPath). |

### AC-16 fixture-drift waiver

`security-baseline.yaml` **is** subject to AC-16 drift-lint (must match
`examples/policies/security-baseline.yaml` byte-for-byte). The other four
fixtures are demo-authored and have no canonical source — they must be
listed in the AC-16 waiver. The waiver contract is co-owned with Worker-4;
the current list is:

```
demo/capture/fixtures/privileged-pod.yaml
demo/capture/fixtures/emergency-pod.yaml
demo/capture/fixtures/emergency-exception.yaml
demo/capture/fixtures/compliant-pod.yaml
```

## Named DOM masks (Principle 4)

Every visual mask applied to a captured frame is named and recorded in
`demo/remotion/public/capture-log.json` so reviewers can audit determinism.

| Mask | CSS selector | Fixed value |
| --- | --- | --- |
| `mask_relative_time_column` | `td[data-col="time"]` | `00:00:00` |
| `mask_sparkline_path` | `path[data-role="sparkline"]` (fallback: `svg path:last-of-type`) | `M0,32 L20,28 L40,22 L60,18 L80,14 L100,10 L120,6` (ascending polyline, per Iter-3 I3-9) |

Each `applyNamedMasks()` invocation in `dashboard.spec.ts` mutates the DOM
in-place via `page.evaluate` before the screenshot, and `mask_*` shell
helpers in `lib.sh` append `{mask_name, css_selector, fixed_value,
applied_at_url}` to the capture log.

## The `apply_and_capture_suppression` contract

Scene 4 is the demo's hardest moment to capture deterministically. The
transactional sequence (Iter-4) is:

1. Record `apply_ts` as **2 seconds before** wall-clock now. This is the
   clock-skew tolerance for `kubectl logs --since-time` against a pod whose
   clock may be a few ticks ahead of the host.
2. `kubectl apply` the PolicyException CR.
3. `kubectl wait --for=condition=Ready policyexception/emergency-deployment`
   — **not** `Active`. The Ready condition is what `controller.go` publishes
   when the exception is reconciled and live in-memory.
4. `kubectl apply` the privileged pod. The admission-webhook now suppresses
   the deny verdict and emits an audit event.
5. Poll `kubectl logs deploy/admission-webhook -c admission-webhook
   --since-time=$apply_ts` filtered with
   `jq -c -e 'select(.suppressed_by and .name=="emergency-pod")'` —
   `.name`, **not** `.resource.name` (the audit-event schema flattens the
   resource name at top level).
6. Once observed, run the same `jq` pipeline (without the deadline loop) and
   write the matching single JSON line to
   `demo/remotion/public/audit/scene-4-audit.json`.
7. Assert the file is non-empty.

## Why `audit.backend.type: stdout` matters (Iter-2 CRITICAL)

The chart default is `audit.backend.type: file`, which writes audit JSON to
a sidecar-mounted volume that `kubectl logs` cannot see. The capture
pipeline consumes audit events exclusively via `kubectl logs`, so the demo
values file must flip the backend to `stdout`. Without this override,
`_wait_for_audit_event_with_suppressed_by` polls forever, the suppression
deadline expires, and the capture fails before any video frame can be
rendered.

`flushInterval: 1s` (vs. the chart default of `10s`) is the matching tweak:
the deadline for the suppressed_by event is 10 seconds, so a 10-second
buffer would routinely miss the first observation.

## Out of scope

- We do **not** modify `scripts/test/*` — Worker-1 owns the shared lib.
- We do **not** author Remotion components — Worker-2 owns `demo/remotion/`.
- We do **not** run `make demo-capture` against a real cluster from this
  worker — Worker-4 owns end-to-end verification.
