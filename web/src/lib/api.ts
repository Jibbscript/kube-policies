import type {
  EvaluationResult,
  Exception,
  MetricsSummary,
  Policy,
  RecentDecisionsResponse,
} from './types';

const BASE_URL = '';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE_URL + path, {
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new ApiError(`${res.status} ${res.statusText}: ${text}`, res.status);
  }
  // Allow 204 / empty bodies.
  if (res.status === 204) return undefined as unknown as T;
  const ct = res.headers.get('content-type') ?? '';
  if (!ct.includes('application/json')) return undefined as unknown as T;
  return (await res.json()) as T;
}

// The policy-manager wraps list responses in {policies:[...], total:N} (and
// {exceptions:[...], total:N} for exceptions). listPolicies/listExceptions
// unwrap so callers can iterate directly. This fixes a long-standing shape
// drift where listPolicies's typed return (Policy[]) didn't match the actual
// JSON body, leaving the Playground policy picker silently empty.
export async function listPolicies(): Promise<Policy[]> {
  const res = await request<{ policies: Policy[]; total: number }>('/api/v1/policies');
  return res.policies ?? [];
}

export function getPolicy(id: string): Promise<Policy> {
  return request<Policy>(`/api/v1/policies/${encodeURIComponent(id)}`);
}

export function testPolicy(id: string, body: unknown): Promise<EvaluationResult> {
  return request<EvaluationResult>(`/api/v1/policies/${encodeURIComponent(id)}/test`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function listExceptions(): Promise<Exception[]> {
  const res = await request<{ exceptions: Exception[]; total: number }>('/api/v1/exceptions');
  return res.exceptions ?? [];
}

export function getMetricsSummary(): Promise<MetricsSummary> {
  return request<MetricsSummary>('/api/metrics/summary');
}

export function getRecentDecisions(limit = 50): Promise<RecentDecisionsResponse> {
  return request<RecentDecisionsResponse>(
    `/api/decisions/recent?limit=${encodeURIComponent(String(limit))}`,
  );
}
