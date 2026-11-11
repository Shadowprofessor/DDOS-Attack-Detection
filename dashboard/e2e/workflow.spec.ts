import { expect, test, type Page } from "@playwright/test";
import { ADMIN_KEY, ANALYST_KEY } from "./keys";

// Runs after smoke.spec.ts (alphabetical), against the same live server + DB.
const AGG = {
  incident_id: "e2e-agg", window_start: 1, pps: 250000, unique_src_ips: 900,
  top_src_ips: [{ key: "10.10.0.21", share: 0.1 }], dst_ips: ["10.0.0.4"],
  protocol_mix: { tcp: 0.98 }, tcp_flag_ratios: { syn: 0.93 }, ml: { label: "Syn", confidence: 0.97 },
};
let incidentId = "";

test.beforeAll(async ({ request }) => {
  const r = await request.post("/api/incidents", {
    headers: { "X-API-Key": ANALYST_KEY },
    data: { title: "Workflow SYN flood", severity: 5, aggregate: AGG },
  });
  expect(r.status()).toBe(201);
  incidentId = (await r.json()).id;
});

async function loginAs(page: Page, key: string) {
  await page.goto("/app/");
  await page.getByLabel("API key").fill(key);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test("analyst works an incident: triage, note, playbook, AI analysis, export", async ({ page }) => {
  await loginAs(page, ANALYST_KEY);
  await page.getByRole("link", { name: "Approvals (view)" }).click(); // analysts see the queue read-only
  await expect(page.getByText(/signed in as an/)).toBeVisible();
  await expect(page.getByRole("button", { name: /Approve/ })).toHaveCount(0);
  await page.goto(`/app/incidents/${incidentId}`);
  await expect(page.getByRole("heading", { name: /Workflow SYN flood/ })).toBeVisible();
  await expect(page.getByText(/Timeline verified/)).toBeVisible();
  // analyst sees only analyst transitions
  await expect(page.getByRole("button", { name: "Move to false positive" })).toHaveCount(0);
  await page.getByRole("button", { name: "Move to triage" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Moved to triage." })).toBeVisible();

  await page.getByLabel("Add a note").fill("Checked upstream NetFlow; matches SYN profile.");
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText("Checked upstream NetFlow; matches SYN profile.")).toBeVisible();

  const step = page.locator("li.step").filter({ hasText: "Confirm SYN ratio" });
  await step.getByRole("button", { name: "Mark done" }).click();
  await expect(step.getByText("done")).toBeVisible();
  const req = page.locator("li.step").filter({ hasText: "Request a rate limit" });
  await req.getByRole("button", { name: "Request action" }).click();
  await expect(req.getByText("done")).toBeVisible();

  await page.getByRole("button", { name: "Run analysis" }).click();
  await expect(page.getByText(/AI recommendation — review before acting/)).toBeVisible();
  await expect(page.getByText("TCP SYN flood", { exact: true })).toBeVisible();

  const [md] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: "Export Markdown" }).click()]);
  expect(md.suggestedFilename()).toBe(`${incidentId}.md`);
  const [pdf] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: "Export PDF" }).click()]);
  expect(pdf.suggestedFilename()).toBe(`${incidentId}.pdf`);
});

test("analyst cannot approve even by calling the API directly", async ({ page }) => {
  await loginAs(page, ANALYST_KEY);
  const status = await page.evaluate(async () => {
    const s = await (await fetch("/api/session")).json();
    const pend = await (await fetch("/actions/pending")).json();
    const id = pend.pending_actions[0].action_id;
    return (await fetch(`/actions/approve/${id}`, { method: "POST", headers: { "X-CSRF-Token": s.csrf_token } })).status;
  });
  expect(status).toBe(403);
});

test("admin approves the requested action and sees the rollback countdown", async ({ page }) => {
  await loginAs(page, ADMIN_KEY);
  await page.getByRole("link", { name: "Approvals" }).click();
  const card = page.getByRole("article", { name: /Pending action/ }).first();
  await expect(card.getByText("10.10.0.21")).toBeVisible();
  await card.getByRole("button", { name: "Approve…" }).click();
  const dlg = page.getByRole("dialog");
  await expect(dlg).toBeVisible();
  await dlg.getByRole("button", { name: "Approve and enforce" }).click();
  await expect(page.getByRole("status").filter({ hasText: /Approve: .* done/ })).toBeVisible();
  // scheduler syncs within ~5 s and schedules the 10-minute auto-rollback
  await expect(page.getByRole("article", { name: /Active action/ }).getByText(/Auto-rollback in/)).toBeVisible({ timeout: 20_000 });

  // keyboard-only extend with a reason
  const active = page.getByRole("article", { name: /Active action/ }).first();
  await active.getByRole("button", { name: "Extend 10 min…" }).focus();
  await page.keyboard.press("Enter");
  await page.keyboard.type("Attack still ongoing upstream");
  await page.getByRole("dialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByRole("status").filter({ hasText: /Extend: .* done/ })).toBeVisible();
});

test("admin contains the incident with a justification and views the CERT-In draft", async ({ page }) => {
  await loginAs(page, ADMIN_KEY);
  await page.goto(`/app/incidents/${incidentId}`);
  await expect(page.getByRole("heading", { name: /Workflow SYN flood/ })).toBeVisible();
  const triage = page.getByRole("button", { name: "Move to triage" });
  if (await triage.count()) {
    await triage.click(); // only if an earlier test did not already triage it
    await expect(page.getByRole("status").filter({ hasText: "Moved to triage." })).toBeVisible();
  }
  await page.getByRole("button", { name: "Move to investigating" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Moved to investigating." })).toBeVisible();
  await page.getByRole("button", { name: "Move to contained" }).click();
  await page.getByRole("dialog").getByRole("textbox").fill("Upstream ACL applied and verified by NOC.");
  await page.getByRole("dialog").getByRole("button", { name: "Mark contained" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Moved to contained." })).toBeVisible();
  await page.getByRole("button", { name: "View report draft" }).click();
  await expect(page.getByLabel("CERT-In report draft")).toContainText("Not submitted to CERT-In");
});

test("live updates: a new incident appears without a reload", async ({ page, request }) => {
  await loginAs(page, ANALYST_KEY);
  await page.goto("/app/incidents");
  await expect(page.getByRole("status").filter({ hasText: "Live" })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText("Live-pushed flood")).toHaveCount(0);
  await request.post("/api/incidents", { headers: { "X-API-Key": ANALYST_KEY }, data: { title: "Live-pushed flood", severity: 3 } });
  await expect(page.getByText("Live-pushed flood")).toBeVisible({ timeout: 6_000 }); // well under the 15 s poll
});
