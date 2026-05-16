import { test as base, type Page, type Route } from '@playwright/test';

/**
 * Mock BFF for Playwright e2e tests.
 *
 * Routes are intercepted at the browser network layer — no real server runs.
 * Each test that wants the default mock fixture should import `test` from this
 * file. Tests can override individual routes by calling `page.route(...)` after
 * the fixture installs the defaults.
 */

const sampleDenyResult = {
  Allowed: false,
  Decision: 'DENY',
  Reason: 'rule violation',
  Message: 'privileged container not allowed',
  Violations: [
    {
      rule_id: 'no-privileged-containers',
      rule_name: 'no-privileged-containers',
      message: 'container "app" runs with securityContext.privileged=true',
      path: 'spec.containers[0].securityContext.privileged',
      severity: 'critical',
      frameworks: ['CIS-5.2.1', 'NSA-Hardening'],
    },
  ],
  Patches: [],
  Metadata: { policy: 'security-baseline' },
};

const samplePolicies = [
  {
    id: 'security-baseline',
    name: 'Security Baseline',
    description: 'Bundled baseline rules',
    enabled: true,
    rules: [
      { id: 'no-privileged-containers', name: 'no-privileged-containers', severity: 'critical' },
      { id: 'no-host-path-volumes', name: 'no-host-path-volumes', severity: 'high' },
      { id: 'no-latest-image-tag', name: 'no-latest-image-tag', severity: 'medium' },
      { id: 'required-security-context', name: 'required-security-context', severity: 'high' },
    ],
  },
];

const sampleMetrics = {
  admission_rps: 0,
  eval_p95_ms: 0,
  denials_per_min: 0,
  policies_loaded: 1,
  audit_buffer: 0,
  top_violating_rules: [],
  policy_manager_degraded: false,
  admission_webhook_degraded: false,
};

async function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

export async function installDefaultMocks(page: Page): Promise<void> {
  await page.route('**/api/v1/policies', (route) => {
    if (route.request().method() === 'GET') return fulfillJson(route, 200, samplePolicies);
    return route.fulfill({ status: 403, body: 'forbidden' });
  });
  await page.route('**/api/v1/policies/security-baseline/test', (route) =>
    fulfillJson(route, 200, sampleDenyResult),
  );
  await page.route('**/api/v1/exceptions', (route) => fulfillJson(route, 200, []));
  await page.route('**/api/metrics/summary', (route) => fulfillJson(route, 200, sampleMetrics));
  await page.route('**/api/decisions/recent**', (route) =>
    fulfillJson(route, 200, { events: [] }),
  );
}

export async function installReadOnlyMocks(page: Page): Promise<void> {
  await page.route('**/api/v1/**', (route) => {
    const method = route.request().method();
    if (method === 'GET') return fulfillJson(route, 200, []);
    return route.fulfill({ status: 403, contentType: 'application/json', body: '{"error":"read-only"}' });
  });
  await page.route('**/api/metrics/summary', (route) => fulfillJson(route, 200, sampleMetrics));
  await page.route('**/api/decisions/recent**', (route) =>
    fulfillJson(route, 200, { events: [] }),
  );
}

export const test = base.extend<{ mockBff: void }>({
  mockBff: [
    async ({ page }, use) => {
      await installDefaultMocks(page);
      await use();
    },
    { auto: true },
  ],
});

export { expect } from '@playwright/test';
