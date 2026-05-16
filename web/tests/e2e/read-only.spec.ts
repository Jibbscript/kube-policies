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

test('write-mode buttons hidden when VITE_ALLOW_WRITES != true', async ({ page }) => {
  await page.goto('/#/policies');
  // The "New policy" button is gated behind import.meta.env.VITE_ALLOW_WRITES === 'true'.
  // At build/dev time this is unset in the default build, so the button must NOT exist.
  await expect(page.getByTestId('new-policy-btn')).toHaveCount(0);

  await page.goto('/#/exceptions');
  await expect(page.getByTestId('new-exception-btn')).toHaveCount(0);
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
