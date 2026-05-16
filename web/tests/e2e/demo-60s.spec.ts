import { test, expect } from "./mock-bff";

test.setTimeout(60_000);

test("Home → Playground → privileged → DENY badge appears", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByTestId("cta-playground")).toBeVisible();
  await page.getByTestId("cta-playground").click();
  await expect(page).toHaveURL(/#\/playground$/);

  // Sample defaults to 'privileged'; click Evaluate.
  await page.getByTestId("sample-picker").selectOption("privileged");
  await page.getByTestId("evaluate-button").click();

  const badge = page.getByTestId("decision-badge");
  await expect(badge).toContainText("DENY", { timeout: 60_000 });
  await expect(page.getByTestId("violation-list")).toContainText(
    "no-privileged-containers",
  );
  await expect(page.getByTestId("verdict-message")).toContainText(
    "privileged container",
  );
});
