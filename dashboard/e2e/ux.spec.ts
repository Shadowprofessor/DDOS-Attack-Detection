import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { ADMIN_KEY, ANALYST_KEY } from "./keys";

// Runs after smoke.spec.ts, before workflow.spec.ts (alphabetical). Every page: axe (0 serious /
// critical), no CSP violations, no horizontal scroll at 375 px.
let incidentId = "";

test.beforeAll(async ({ request }) => {
  const r = await request.post("/api/incidents", {
    headers: { "X-API-Key": ANALYST_KEY },
    data: { title: "UX audit flood", severity: 4, aggregate: { incident_id: "ux", window_start: 1, pps: 5000, top_src_ips: [{ key: "10.1.1.1", share: 0.2 }], dst_ips: ["10.0.0.4"], protocol_mix: { udp: 0.9 } } },
  });
  incidentId = (await r.json()).id;
});

async function loginAs(page: Page, key: string) {
  await page.goto("/app/");
  await page.getByLabel("API key").fill(key);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

function watchCsp(page: Page): string[] {
  const out: string[] = [];
  page.on("console", (m) => {
    if (/Content Security Policy|Refused to (execute|load|apply|connect)/i.test(m.text())) out.push(m.text());
  });
  return out;
}

const PAGES: [string, string][] = [
  ["/app/overview", "Overview"], ["/app/incidents", "Incidents"], ["/app/approvals", "Approvals"],
  ["/app/live-attack", "Live attack"], ["/app/live", "Live feed"], ["/app/replay", "Replay"], ["/app/analyst", "AI analyst"], ["/app/settings", "Settings & health"],
];

test("every page: axe has no serious/critical issues and the CSP holds", async ({ page }) => {
  const csp = watchCsp(page);
  await loginAs(page, ADMIN_KEY);
  for (const [path, heading] of [...PAGES, [`/app/incidents/${incidentId}`, "UX audit flood"] as [string, string]]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 }).filter({ hasText: heading })).toBeVisible();
    await page.waitForLoadState("networkidle");
    const res = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze();
    const bad = res.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`), path).toEqual([]);
  }
  expect(csp).toEqual([]);
});

test("every page fits a 375 px viewport", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  await loginAs(page, ADMIN_KEY);
  for (const [path] of [...PAGES, [`/app/incidents/${incidentId}`, ""] as [string, string]]) {
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, path).toBeLessThanOrEqual(0);
  }
});

test("reduced motion is respected (no running animations)", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await loginAs(page, ANALYST_KEY);
  const running = await page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").length);
  expect(running).toBe(0);
});

test("live feed shows a scored flow pushed over the stream", async ({ page, request }) => {
  await loginAs(page, ANALYST_KEY);
  await page.getByRole("link", { name: "Live feed" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Stream live" })).toBeVisible({ timeout: 10_000 });
  await request.post("/score/flow", { headers: { "X-API-Key": ANALYST_KEY },
    data: { features: { src_ip: "10.66.6.6", dst_ip: "10.0.0.4", Protocol: 6, "SYN Flag Count": 100 } } });
  await expect(page.getByRole("listitem").filter({ hasText: "10.66.6.6" }).first()).toBeVisible({ timeout: 10_000 });
  await page.getByRole("button", { name: "Pause" }).click();
  await expect(page.getByRole("button", { name: /Resume/ })).toHaveAttribute("aria-pressed", "true");
});

test("replay creates a replay incident", async ({ page }) => {
  await loginAs(page, ANALYST_KEY);
  await page.getByRole("link", { name: "Replay" }).click();
  await page.getByLabel("Scenario").selectOption("syn_flood");
  await page.getByLabel(/Speed/).selectOption("10000");
  await page.getByRole("button", { name: "Run replay" }).click();
  await expect(page.getByText(/\[REPLAY\] TCP SYN flood/)).toBeVisible();
  await page.getByRole("link", { name: /^INC-/ }).click();
  await expect(page.getByText("replay", { exact: true }).first()).toBeVisible();
});

test("AI analyst chat cannot act but still advises, and answers general questions", async ({ page }) => {
  await loginAs(page, ANALYST_KEY);
  await page.getByRole("link", { name: "AI analyst" }).click();
  await page.getByLabel("Question").fill("Please block IP 10.1.1.1 now");
  await page.getByRole("button", { name: "Ask" }).click();
  await expect(page.getByText(/SAFETY ENFORCEMENT NOTICE/)).toBeVisible();
  await expect(page.getByText(/Approvals page/).first()).toBeVisible();
  await expect(page.getByText(/READ_ONLY_ADVISORY/).first()).toBeVisible();
  await page.getByLabel("Question").fill("How do I secure the network against a SYN flood?");
  await page.getByRole("button", { name: "Ask" }).click();
  await expect(page.getByText(/tcp_syncookies/).first()).toBeVisible(); // offline in CI: rule-based guidance, now rendered as Markdown code
});

test("settings shows release + config, never a secret", async ({ page }) => {
  await loginAs(page, ANALYST_KEY);
  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByText(/^v\d+\.\d+\.\d+$/)).toBeVisible();
  const html = await page.content();
  expect(html).not.toContain(ANALYST_KEY);
  expect(html).not.toContain(ADMIN_KEY);
});

test("legacy dashboard URLs redirect to the SOC app (removed in v5.0.0)", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/app\/?$/);
});
