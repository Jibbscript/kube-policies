// TypeScript mirrors of the Go JSON shapes.

export type Decision = 'ALLOW' | 'DENY';

export interface PolicyViolation {
  rule_id: string;
  rule_name?: string;
  message: string;
  path?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  frameworks?: string[];
}

export interface JSONPatch {
  op: 'add' | 'remove' | 'replace' | 'move' | 'copy' | 'test';
  path: string;
  value?: unknown;
}

export interface EvaluationResult {
  Allowed: boolean;
  Decision: Decision;
  Reason?: string;
  Message?: string;
  Violations: PolicyViolation[];
  Patches: JSONPatch[];
  Metadata: Record<string, unknown>;
}

export interface Rule {
  id: string;
  name: string;
  description?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  rego?: string;
  frameworks?: string[];
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  rules: Rule[];
  frameworks?: string[];
  created_at?: string;
  updated_at?: string;
}

export interface Exception {
  id: string;
  policy_id: string;
  rule_id?: string;
  namespace?: string;
  resource?: string;
  reason: string;
  expires_at?: string;
  created_at?: string;
}

export interface TopRule {
  rule_id: string;
  count: number;
}

export interface MetricsSummary {
  admission_rps: number;
  eval_p95_ms: number;
  denials_per_min: number;
  policies_loaded: number;
  audit_buffer: number;
  top_violating_rules: TopRule[];
  policy_manager_degraded: boolean;
  admission_webhook_degraded: boolean;
}

export interface PublicEvent {
  decision: Decision;
  namespace: string;
  kind: string;
  rule_id?: string;
  policy_id?: string;
  timestamp: string;
  name?: string;
  latency_ms?: number;
}

export interface RecentDecisionsResponse {
  events: PublicEvent[];
  degraded?: boolean;
}
