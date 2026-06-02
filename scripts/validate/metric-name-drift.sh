#!/usr/bin/env bash
# IRM-WU-15 (NIST CA-7, CM-3, SI-4, SA-11): metric-name drift guard.
#
# Every kube_policies_* metric referenced by an alert/recording rule MUST exist
# in internal/metrics/collector.go. This catches the failure mode that produced
# the original divergent rule_files reference: an alert silently pointing at a
# metric name the code never emits, so it can never fire.
#
# How it works:
#   1. Derive the authoritative set of full metric names from collector.go by
#      pairing each Namespace/Subsystem/Name string literal.
#   2. Extract every kube_policies_<underscore> token referenced in the rule
#      files (recording-rule names use colons — kube_policies:... — and are
#      excluded by the token regex; they are derived, not collector metrics).
#   3. Strip histogram suffixes (_bucket/_count/_sum) and assert each token is in
#      the authoritative set.
#
# Usage: scripts/validate/metric-name-drift.sh <rule-file>...
set -euo pipefail

COLLECTOR="internal/metrics/collector.go"
[ -f "$COLLECTOR" ] || { echo "ERROR: $COLLECTOR not found (run from repo root)" >&2; exit 2; }
[ "$#" -gt 0 ] || { echo "ERROR: no rule files given" >&2; exit 2; }

# 1. Authoritative full metric names from collector.go. A new metric block
#    starts at Namespace:, which resets the per-block Subsystem so a metric that
#    omits Subsystem: (legal — namespace_name) cannot inherit the previous
#    block's subsystem and fabricate a wrong name.
valid="$(awk '
  /Namespace:/ { if (match($0, /"[^"]+"/)) { ns=substr($0,RSTART+1,RLENGTH-2); ss="" } }
  /Subsystem:/ { if (match($0, /"[^"]+"/)) ss=substr($0,RSTART+1,RLENGTH-2) }
  /Name:[[:space:]]*"/ {
    if (match($0, /"[^"]+"/)) {
      nm=substr($0,RSTART+1,RLENGTH-2)
      if (ss == "") print ns"_"nm; else print ns"_"ss"_"nm
    }
  }
' "$COLLECTOR" | sort -u)"

if [ -z "$valid" ]; then
  echo "ERROR: could not derive any metric names from $COLLECTOR" >&2
  exit 2
fi

# 2. Tokens referenced in the rule files.
tokens="$(grep -ohE 'kube_policies_[a-z0-9_]+' "$@" | sort -u || true)"

# 3. Check each referenced token against the authoritative set.
missing=0
while IFS= read -r tok; do
  [ -n "$tok" ] || continue
  base="$tok"
  case "$tok" in
    *_bucket) base="${tok%_bucket}" ;;
    *_count)  base="${tok%_count}" ;;
    *_sum)    base="${tok%_sum}" ;;
  esac
  if ! grep -qxF "$base" <<<"$valid"; then
    echo "DRIFT: rule files reference '$tok' but collector.go emits no metric '$base'" >&2
    missing=1
  fi
done <<<"$tokens"

if [ "$missing" -ne 0 ]; then
  echo "" >&2
  echo "Authoritative kube_policies_* metrics in $COLLECTOR:" >&2
  echo "$valid" | sed 's/^/  - /' >&2
  exit 1
fi

echo "metric-name drift check: OK ($(wc -l <<<"$tokens" | tr -d ' ') referenced names all exist in collector.go)"
