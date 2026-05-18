// dashboard.spec.ts — Playwright capture spec for the kube-policies SPA.
//
// Invoked by demo/capture/lib.sh::capture_dashboard_shots. For each route
// listed in PAGES we:
//   1. navigate to http://localhost:8081<route>
//   2. wait for the page-specific data-testid (proxy for "render complete")
//   3. apply the two named DOM masks (Principle 4) deterministically
//   4. screenshot to demo/remotion/public/screenshots/dashboard-<route>-<variant>.png
//
// The masks are applied in-page via page.evaluate so the resulting PNG is
// pixel-stable across runs (no relative-time drift, no live sparklines).
import { test, expect } from "@playwright/test";
import path from "node:path";

const BASE_URL = process.env.DASHBOARD_URL ?? "http://localhost:8081";
const SCREENSHOT_DIR = path.resolve(
  __dirname,
  "..",
  "remotion",
  "public",
  "screenshots",
);

interface PageSpec {
  route: string;
  variant: string;
  testid: string;
}

// Routes use svelte-spa-router (hash-based). Real route paths from
// web/src/App.svelte: `/`, `/live`, `/metrics`, `/exceptions`.
// testids verified against the actual web/src/routes/*.svelte renderings.
const PAGES: PageSpec[] = [
  { route: "/#/live",       variant: "livedecisions", testid: "decisions-tbody" },
  { route: "/#/metrics",    variant: "metrics",       testid: "metric-grid" },
  { route: "/#/exceptions", variant: "exceptions",    testid: "exceptions-table" },
  { route: "/#/",           variant: "overview",      testid: "home-counters" },
];

// Named masks per plan §5.3.3 + Iter-3 I3-9.
//
// mask_relative_time_column: replace every relative-time cell with "00:00:00".
// mask_sparkline_path:       replace every sparkline path's `d` attribute with
//                            a fixed ascending polyline. Prefers
//                            path[data-role="sparkline"] and falls back to the
//                            last <path> inside each <svg> for older markup.
function applyNamedMasks(): string {
  // The string is shipped verbatim into page.evaluate (which runs in the
  // browser as JavaScript, NOT TypeScript). Do NOT introduce TS-only syntax
  // (type annotations, `as` casts) inside this template — it will fail at
  // eval-time with "Missing initializer in const declaration".
  return `
    (function () {
      document.querySelectorAll('td[data-col="time"]').forEach(function (el) {
        el.textContent = '00:00:00';
      });

      var FIXED_D = 'M0,32 L20,28 L40,22 L60,18 L80,14 L100,10 L120,6';
      var sparklines = document.querySelectorAll('path[data-role="sparkline"]');
      if (sparklines.length === 0) {
        var fallback = [];
        document.querySelectorAll('svg').forEach(function (svg) {
          var paths = svg.querySelectorAll('path');
          if (paths.length > 0) fallback.push(paths[paths.length - 1]);
        });
        sparklines = fallback;
      }
      sparklines.forEach(function (p) { p.setAttribute('d', FIXED_D); });
    })();
  `;
}

test.use({
  viewport: { width: 1920, height: 1080 },
  deviceScaleFactor: 1,
});

for (const page of PAGES) {
  test(`dashboard ${page.variant}`, async ({ page: browser }) => {
    // Use "domcontentloaded" instead of "networkidle" — the dashboard polls
    // /api/v1/decisions and /api/v1/metrics every 2-3s, so networkidle never
    // fires and the test times out at 30s.
    await browser.goto(`${BASE_URL}${page.route}`, { waitUntil: "domcontentloaded" });
    // Give the SPA a brief moment to render past initial mount + first
    // /api fetches, so populated tiles + rows are visible.
    await browser.waitForTimeout(2500);

    // Use toBeAttached rather than toBeVisible — the metric-grid + exceptions-table
    // containers exist in DOM unconditionally but may be zero-height when the
    // local vite preview can't reach the policy-manager API (returns 500 → no
    // tiles or rows rendered). The screenshot still captures the page chrome,
    // which is what Scene 5 needs.
    await expect(
      browser.locator(`[data-testid="${page.testid}"]`),
    ).toBeAttached({ timeout: 10_000 });

    await browser.evaluate(applyNamedMasks());

    // Give the DOM one frame to settle after the mask mutation before snap.
    await browser.waitForTimeout(50);

    await browser.screenshot({
      path: path.join(
        SCREENSHOT_DIR,
        `dashboard-${page.variant}.png`,
      ),
      fullPage: true,
    });
  });
}

// Optional Grafana branch — selected by capture_grafana_shots via --grep.
test("grafana overview", async ({ page: browser }) => {
  const grafanaUrl =
    process.env.GRAFANA_URL ?? "http://localhost:3000";
  await browser.goto(
    `${grafanaUrl}/d/kube-policies-overview/kube-policies-overview?orgId=1&kiosk`,
    { waitUntil: "domcontentloaded" },
  );
  await browser.waitForTimeout(1_500);
  await browser.evaluate(applyNamedMasks());
  await browser.waitForTimeout(50);
  await browser.screenshot({
    path: path.join(SCREENSHOT_DIR, "dashboard-grafana-overview.png"),
    fullPage: true,
  });
});
