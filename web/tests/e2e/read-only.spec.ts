import { test as base, expect } from '@playwright/test';
import { installReadOnlyMocks } from './mock-bff';

const test = base.extend<{ readOnly: void }>({
  readOnly: [
    async ({ page }, use) => {
      await installReadOnlyMocks(page);
      await use();
    },
    { auto: true },
  ],
});

test('direct POST to /api/v1/policies returns 403', async ({ page }) => {
  await page.goto('/');
  const status = await page.evaluate(async () => {
    const r = await fetch('/api/v1/policies', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'x', name: 'x' }),
    });
    return r.status;
  });
  expect(status).toBe(403);
});
