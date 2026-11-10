import { expect, test } from "@playwright/test";
import { ADMIN_KEY } from "./keys";

// Opt-in: SCREENSHOTS=1 npx playwright test e2e/zz-screenshots.spec.ts  -> docs/img/*.png
test.skip(!process.env.SCREENSHOTS, "screenshots are generated on demand");

test("capture README screenshots", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 860 });
  await page.goto("/app/");
  await page.getByLabel("API key").fill(ADMIN_KEY);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  for (const [path, file] of [["/app/overview", "overview"], ["/app/incidents", "incidents"], ["/app/approvals", "approvals"],
    ["/app/live", "live-feed"], ["/app/replay", "replay"], ["/app/settings", "settings"]]) {
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    await page.screenshot({ path: `../docs/img/${file}.png`, fullPage: false });
  }
  await page.goto("/app/incidents?min_severity=4");
  await page.getByRole("link", { name: /^INC-/ }).first().click();
  await expect(page.getByText(/Timeline verified/)).toBeVisible();
  await page.waitForLoadState("networkidle");
  await page.screenshot({ path: "../docs/img/incident-detail.png", fullPage: true });
});
