import { expect, test, type Page } from "@playwright/test";
import { ADMIN_KEY, ANALYST_KEY } from "./keys";

const XSS = `<img src=x onerror="window.__xss=1">XSS-TITLE`;

test.beforeAll(async ({ request }) => {
  const h = { "X-API-Key": ANALYST_KEY };
  // idempotent: a worker restart after a failure re-runs beforeAll
  const existing = await (await request.get("/api/incidents?limit=1", { headers: h })).json();
  if (existing.total > 0) return;
  for (let i = 0; i < 28; i++) {
    const r = await request.post("/api/incidents", { headers: h, data: { title: `Seed flood ${i}`, severity: (i % 5) + 1 } });
    expect(r.status()).toBe(201);
  }
  const r = await request.post("/api/incidents", { headers: h, data: { title: XSS, severity: 5 } });
  expect(r.status()).toBe(201);
});

/** Status of a request made by the page itself (so the browser's cookie rules apply). */
async function browserFetch(page: Page, path: string, method = "GET", body?: unknown): Promise<number> {
  return page.evaluate(
    async ([p, m, b]) => (await fetch(p as string, { method: m as string, credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: b === undefined ? undefined : JSON.stringify(b) })).status,
    [path, method, body] as const,
  );
}

function collectCspViolations(page: Page): string[] {
  const out: string[] = [];
  page.on("console", (m) => {
    if (/Content Security Policy|Refused to (execute|load|apply)/i.test(m.text())) out.push(m.text());
  });
  return out;
}

async function loginAs(page: Page, key: string) {
  await page.goto("/app/");
  await page.getByLabel("API key").fill(key);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test("analyst logs in, sees overview, CSP holds", async ({ page }) => {
  const csp = collectCspViolations(page);
  const resp = await page.goto("/app/");
  const header = resp?.headers()["content-security-policy"] ?? "";
  expect(header).toContain("script-src 'self'");
  expect(header).not.toContain("unsafe-inline");
  await loginAs(page, ANALYST_KEY);
  await expect(page.getByText("Open incidents")).toBeVisible();
  await expect(page.getByText("CERT-In reporting timers")).toBeVisible();
  await expect(page.locator(".role")).toHaveText("analyst");
  expect(csp).toEqual([]);
});

test("bad key shows an error and no session", async ({ page }) => {
  await page.goto("/app/");
  await page.getByLabel("API key").fill("definitely-wrong-key");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toHaveText("Invalid API key.");
  expect(await browserFetch(page, "/api/session")).toBe(401);
});

test("incident list filters, sorts and paginates", async ({ page }) => {
  await loginAs(page, ANALYST_KEY);
  await page.getByRole("link", { name: "Incidents" }).click();
  await expect(page.getByText(/Page 1 of 2 · 29 incidents/)).toBeVisible();
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.getByText(/Page 2 of 2/)).toBeVisible();
  await page.getByLabel("Min severity").selectOption("5");
  await expect(page.getByText(/Page 1 of 1 · 6 incidents/)).toBeVisible();
  await page.getByLabel("Sort").selectOption("severity_asc");
  await expect(page).toHaveURL(/sort=severity_asc/);
});

test("XSS payload in an incident title renders as text", async ({ page }) => {
  let dialog = false;
  page.on("dialog", (d) => {
    dialog = true;
    void d.dismiss();
  });
  await loginAs(page, ANALYST_KEY);
  await page.goto("/app/incidents?min_severity=5");
  await expect(page.getByText(XSS)).toBeVisible();
  expect(await page.locator("table img").count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
  expect(dialog).toBe(false);
});

test("admin role shown; logout ends the session", async ({ page }) => {
  await loginAs(page, ADMIN_KEY);
  await expect(page.locator(".role")).toHaveText("admin");
  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page.getByLabel("API key")).toBeVisible();
  expect(await browserFetch(page, "/api/session")).toBe(401);
});

test("session cookie is HttpOnly + SameSite=Strict and the key is never stored", async ({ page, context }) => {
  await loginAs(page, ANALYST_KEY);
  const c = (await context.cookies()).find((x) => x.name === "ddos_session");
  expect(c?.httpOnly).toBe(true);
  expect(c?.sameSite).toBe("Strict");
  expect(c?.secure).toBe(true);
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie);
  expect(stored).not.toContain(ANALYST_KEY);
});

test("mutation without CSRF token is rejected", async ({ page }) => {
  await loginAs(page, ANALYST_KEY);
  expect(await browserFetch(page, "/api/session")).toBe(200); // the session cookie IS sent
  expect(await browserFetch(page, "/api/incidents", "POST", { title: "no csrf here", severity: 2 })).toBe(403);
});

test("no horizontal scroll at 375px", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  await loginAs(page, ANALYST_KEY);
  for (const path of ["/app/overview", "/app/incidents"]) {
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, path).toBeLessThanOrEqual(0);
  }
});
