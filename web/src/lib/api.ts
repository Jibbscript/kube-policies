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

export function listPolicies(): Promise<Policy[]> {
  return request<Policy[]>('/api/v1/policies');
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

export function listExceptions(): Promise<Exception[]> {
  return request<Exception[]>('/api/v1/exceptions');
}

export function getMetricsSummary(): Promise<MetricsSummary> {
  return request<MetricsSummary>('/api/metrics/summary');
}

export function getRecentDecisions(limit = 50): Promise<RecentDecisionsResponse> {
  return request<RecentDecisionsResponse>(
    `/api/decisions/recent?limit=${encodeURIComponent(String(limit))}`,
  );
}
