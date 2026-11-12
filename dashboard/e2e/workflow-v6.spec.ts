import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
// v6.0.0: alerts (toast + reason + CERT-In deadline, dedupe, test alert), the explanation on the
// incident page, and the full demo path approve -> enforcer applied -> traffic drops on the chart.
// CI has no OVS: the lab enforcer is mocked by calling the report API it uses through the bridge.
// Runs after workflow-containment (alphabetical) and before workflow.spec.
import { ADMIN_KEY, ANALYST_KEY } from "./keys";

const H = { "X-API-Key": ANALYST_KEY };
const VICTIM = "10.99.0.10";

async function loginAs(page: Page, key: string) {
  await page.goto("/app/");
  await page.getByLabel("API key").fill(key);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "Live" })).toBeVisible({ timeout: 10_000 });
}

const liveIncident = (title: string, detail: string) => ({
  title, severity: 4,
  aggregate: {
    incident_id: `agg-${title.length}`, window_start: 1, pps: 2997, bps: 9.6e5, unique_src_ips: 50, dst_ips: [VICTIM],
    protocol_mix: { tcp: 1.0 }, tcp_flag_ratios: { syn: 0.5, rst: 0.5 }, tcp_payload_share: 0.0,
    top_src_ips: [{ key: "10.99.0.121", share: 0.03 }],
    alert_history: [{ ts: 1, layer: "L1", rule: "SYN flood", detail }],
  },
});

const win = (t: number, pps: number) => ({
  start: t, end: t + 1, dst: VICTIM, packets: pps, bytes: pps * 40, pps, bps: pps * 320,
  unique_src: pps ? 50 : 0, src_entropy: pps ? 5.6 : 0, proto_mix: pps ? { tcp: 1.0 } : {}, tcp_flags: pps ? { syn: 0.5, rst: 0.5 } : {},
  syn_rate: pps / 2, conn_rate: 0, pkt_size: { mean: 54, p50: 54, p95: 54, max: 54 },
  top_talkers: pps ? [{ ip: "10.99.0.121", packets: Math.round(pps / 50) }] : [], top_dst_ports: [],
});

async function postWindows(request: APIRequestContext, windows: object[]) {
  expect((await request.post("/api/live/windows", { headers: H, data: { sensor: "e2e-v6", windows } })).status()).toBe(200);
}

test("a new live incident pops an alert toast with its reason and CERT-In deadline, once", async ({ page, request }) => {
  await loginAs(page, ANALYST_KEY);
  await page.getByRole("link", { name: "Approvals (view)" }).click(); // alerts show on any page
  const title = "[LIVE] L1 SYN Flood toward 10.99.0.10 (e2e alert)";
  const reason = "2,997 pps toward 10.99.0.10 >= 500 pps critical threshold; SYN 50% of TCP";
  const r = await request.post("/api/incidents", { headers: H, data: liveIncident(title, reason) });
  expect(r.status()).toBe(201);
  const id = (await r.json()).id as string;

  const toast = page.getByRole("alert").filter({ hasText: title });
  await expect(toast).toBeVisible();
  await expect(toast).toContainText("high");
  await expect(toast).toContainText(reason);
  await expect(toast).toContainText(/CERT-In report due by \d\d:\d\d UTC \(6 h\)/);

  // the same attack re-opened within 2 minutes: deduplicated, no second toast
  expect((await request.post("/api/incidents", { headers: H, data: liveIncident(title, reason) })).status()).toBe(201);
  await page.waitForTimeout(1500);
  await expect(page.getByRole("alert").filter({ hasText: title })).toHaveCount(1);

  // the toast links to the incident, whose page explains why it was flagged
  await toast.getByRole("link", { name: `Open ${id}` }).click();
  await expect(page).toHaveURL(new RegExp(`/app/incidents/${id}$`));
  await expect(page.getByRole("alert").filter({ hasText: title })).toHaveCount(0); // dismissed on open
  const why = page.getByRole("heading", { name: "Why it was flagged" }).locator("..");
  await expect(why).toBeVisible();

  // dismiss button works for the next one
  await request.post("/api/incidents", { headers: H, data: liveIncident(`${title} #2`, reason) });
  const t2 = page.getByRole("alert").filter({ hasText: `${title} #2` });
  await expect(t2).toBeVisible();
  await t2.getByRole("button", { name: /Dismiss alert/ }).click();
  await expect(t2).toHaveCount(0);
});

test("settings: admin sends a test alert; recent alerts are listed; webhook is off and no secret shown", async ({ page }) => {
  await loginAs(page, ANALYST_KEY);
  await page.getByRole("link", { name: "Settings" }).click();
  const card = page.getByRole("heading", { name: "Alerts" }).locator("..");
  await expect(card).toContainText("off (set DDOS_ALERT_WEBHOOK_URL)");
  await expect(card.getByRole("button", { name: "Send test alert" })).toHaveCount(0); // analyst: no button
  await expect(card.getByRole("list", { name: "Recent alerts" })).toContainText("e2e alert");
  await page.getByRole("button", { name: "Log out" }).click();

  await loginAs(page, ADMIN_KEY);
  await page.getByRole("link", { name: "Settings" }).click();
  const admin = page.getByRole("heading", { name: "Alerts" }).locator("..");
  await admin.getByRole("button", { name: "Send test alert" }).click();
  await expect(admin.getByRole("status")).toContainText("Test alert sent.");
  await expect(page.getByRole("status").filter({ hasText: "Test alert" }).first()).toBeVisible(); // medium -> polite toast
  await expect(admin.getByRole("list", { name: "Recent alerts" })).toContainText("Test alert");
  expect(await page.content()).not.toMatch(/discord\.com\/api\/webhooks|hooks\.slack\.com/);
});

test("demo path: live attack -> agent plan -> admin approves -> enforcer applied -> traffic drops on the chart", async ({ page, request }) => {
  expect((await request.post("/api/live/reset", { headers: H })).status()).toBe(204);
  const t0 = Math.floor(Date.now() / 1000);
  await postWindows(request, [win(t0, 40), win(t0 + 1, 2997), win(t0 + 2, 2990)]);
  const inc = await (await request.post("/api/incidents", {
    headers: H, data: liveIncident("[LIVE] L1 SYN Flood toward 10.99.0.10 (e2e demo)", "2,997 pps toward 10.99.0.10; SYN 50% of TCP"),
  })).json();

  // the analyst asks the agent; it recommends, it does not act
  await loginAs(page, ANALYST_KEY);
  await page.goto(`/app/incidents/${inc.id}`);
  await page.getByRole("button", { name: "Ask the agent" }).click();
  const plan = page.getByRole("heading", { name: "AI containment plan" }).locator("../..");
  await expect(plan).toContainText("recommendations only");
  const row = plan.getByRole("row").filter({ hasText: "LAB_OVS" }).first();
  await row.getByRole("button", { name: "Propose…" }).click();
  await expect(page.getByRole("status").filter({ hasText: /PENDING until an admin approves/ })).toBeVisible();
  await page.getByRole("button", { name: "Log out" }).click();

  // a human admin approves on the website
  await loginAs(page, ADMIN_KEY);
  await page.getByRole("link", { name: "Approvals" }).click();
  const card = page.getByRole("article", { name: /Pending action/ }).filter({ hasText: inc.id });
  await card.getByRole("button", { name: "Approve…" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Approve and enforce" }).click();
  await expect(page.getByRole("status").filter({ hasText: /Approve: .* done/ })).toBeVisible();

  // approved -> queued; the (mocked) lab enforcer applies it and reports back
  const queue = await (await request.get("/api/lab/enforcement/queue", { headers: H })).json();
  const item = queue.queue.find((q: { op: string }) => q.op === "apply");
  expect(item).toBeTruthy();
  await page.goto("/app/live-attack");
  await expect(page.getByText("Stream live")).toBeVisible();
  await expect(page.getByRole("img", { name: /Packets per second.*current 3\.0k pkt\/s/ })).toBeVisible();
  expect((await request.post("/api/lab/enforcement/report", {
    headers: H, data: { action_id: item.action_id, state: "applied", detail: "drop rule installed (mock enforcer)", ts: Date.now() / 1000 },
  })).status()).toBe(200);
  const lab = page.getByRole("heading", { name: "Lab containment (human-approved)" }).locator("..");
  await expect(lab).toContainText("applied");

  // the switch drops the attack: the victim's traffic falls to 0 on the chart and the L1 alert clears
  await postWindows(request, [3, 4, 5, 6, 7, 8].map((i) => win(t0 + i, 0)));
  await expect(page.getByRole("img", { name: /Packets per second.*current 0 pkt\/s/ })).toBeVisible();
  await expect(page.getByText("No active L1 alert.")).toBeVisible();
});
