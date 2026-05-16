import type { MetricsSummary } from "./types";

export interface MetricTileData {
  key: string;
  label: string;
  value: string;
  hint?: string;
}

/** Pure helper — produces the tile values shown on the Metrics route. */
export function metricsToTiles(m: MetricsSummary): MetricTileData[] {
  return [
    { key: "rps", label: "Admission RPS", value: m.admission_rps.toFixed(2) },
    { key: "p95", label: "Eval p95 (ms)", value: m.eval_p95_ms.toFixed(1) },
    {
      key: "denials",
      label: "Denials / min",
      value: m.denials_per_min.toFixed(1),
    },
    {
      key: "policies",
      label: "Policies loaded",
      value: String(m.policies_loaded),
    },
    { key: "audit", label: "Audit buffer", value: String(m.audit_buffer) },
    {
      key: "pm",
      label: "Policy mgr",
      value: m.policy_manager_degraded ? "DEGRADED" : "OK",
    },
    {
      key: "admit",
      label: "Admission webhook",
      value: m.admission_webhook_degraded ? "DEGRADED" : "OK",
    },
    {
      key: "top",
      label: "Top rule",
      value: m.top_violating_rules[0]?.rule_id ?? "—",
      hint: m.top_violating_rules[0]
        ? `${m.top_violating_rules[0].count} hits`
        : undefined,
    },
  ];
}

/** Simple SVG path for a sparkline given equal-spaced data points. */
export function sparklinePath(
  values: number[],
  width: number,
  height: number,
): string {
  if (values.length === 0) return "";
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const step = values.length > 1 ? width / (values.length - 1) : 0;
  return values
    .map((v, i) => {
      const x = i * step;
      const y = height - ((v - min) / range) * height;
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}
