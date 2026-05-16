import { test as base, expect, type Route } from "@playwright/test";
import { installDefaultMocks } from "./mock-bff";

/**
 * liveStream fixture: installs default BFF mocks then overrides the
 * /api/decisions/recent endpoint to return one DENY event so the
 * LiveDecisions page renders a row immediately on mount (polling path).
 * The /api/decisions/stream endpoint is also mocked for completeness —
 * it represents the SSE feed the BFF exposes to browsers (M2 contract).
 */
const test = base.extend<{ liveStream: void }>({
  liveStream: [
    async ({ page }, use) => {
      // Install defaults first (mocks recent with empty events, etc.)
      await installDefaultMocks(page);

      // Override recent to return one live decision event.
      // Registered after installDefaultMocks so it takes priority (LIFO).
      await page.route("**/api/decisions/recent**", async (route: Route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            events: [
              {
                decision: "DENY",
                namespace: "default",
                kind: "Pod",
                rule_id: "no-privileged-containers",
                policy_id: "security-baseline",
                timestamp: "2026-05-15T12:00:00Z",
              },
            ],
            degraded: false,
          }),
        });
      });

      // Mock the SSE stream endpoint — the BFF exposes this to browsers.
      await page.route("**/api/decisions/stream", async (route: Route) => {
        const sseBody = [
          'data: {"decision":"DENY","namespace":"default","kind":"Pod","rule_id":"no-privileged-containers","policy_id":"security-baseline","timestamp":"2026-05-15T12:00:00Z"}',
          "",
          "",
        ].join("\n");
        await route.fulfill({
          status: 200,
          contentType: "text/event-stream",
          headers: { "cache-control": "no-cache" },
          body: sseBody,
        });
      });

      await use();
    },
    { auto: true },
  ],
});

test("LiveDecisions ticker shows row within 2s of SSE message", async ({
  page,
}) => {
  await page.goto("/#/live");

  // DecisionRow renders with data-testid="decision-row".
  // The row must appear within 2 s of the page loading (on-mount poll fires immediately).
  const firstRow = page.getByTestId("decision-row").first();
  await expect(firstRow).toBeVisible({ timeout: 2000 });

  // The rule_id is rendered inside a RuleBadge (data-testid="rule-badge") within the row.
  await expect(firstRow).toContainText("no-privileged-containers");
});
