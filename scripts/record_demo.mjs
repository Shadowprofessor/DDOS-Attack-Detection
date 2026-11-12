// Browser half of scripts/record_demo.py (v6.1.0). Uses the dashboard's Playwright install.
// Signs in as the admin, watches Live attack, and when the replayed attack opens an incident it:
// asks the agent (analyst key), proposes the top lab step (analyst key; PENDING), waits APPROVE_AFTER s
// from the alert, approves it in the UI as the admin, then a MOCK enforcer reports "applied".
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const require = createRequire(join(process.cwd(), "package.json"));
const { chromium } = require("@playwright/test");

const { BASE, FRAMES, ANALYST, ADMIN } = process.env;
const APPROVE_AFTER = Number(process.env.APPROVE_AFTER ?? 33.6) * 1000;
const DURATION = Number(process.env.DURATION ?? 58) * 1000;
mkdirSync(FRAMES, { recursive: true });

const H = { "X-API-Key": ANALYST, "Content-Type": "application/json" };
const api = async (path, init = {}) => {
  const r = await fetch(BASE + path, { ...init, headers: { ...H, ...(init.headers ?? {}) } });
  return { status: r.status, body: r.status === 204 ? null : await r.json().catch(() => null) };
};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
await page.goto(`${BASE}/app/`);
await page.getByLabel("API key").fill(ADMIN);
await page.getByRole("button", { name: "Sign in" }).click();
await page.getByRole("heading", { name: "Overview" }).waitFor();
await page.getByRole("link", { name: "Live attack" }).click();

let n = 0;
const events = {};
const t0 = Date.now();
const snap = async () => page.screenshot({ path: join(FRAMES, `${String(n++).padStart(4, "0")}.png`) });
let shooting = true;
const shooter = (async () => {
  while (shooting) {
    const t = Date.now();
    await snap().catch(() => {});
    await new Promise((r) => setTimeout(r, Math.max(0, 500 - (Date.now() - t))));
  }
})();

// 1. wait for the live incident
let inc = null;
while (!inc && Date.now() - t0 < DURATION) {
  const { body } = await api("/api/incidents?limit=5&include_replay=false");
  inc = (body?.items ?? []).find((i) => String(i.title).startsWith("[LIVE]")) ?? null;
  if (!inc) await new Promise((r) => setTimeout(r, 300));
}
if (!inc) throw new Error("no live incident opened");
const tAlert = Date.now();
events.alert_s = (tAlert - t0) / 1000;

// 2. agent plan + propose the top lab step (what demo_assist.py does; analyst key, cannot approve)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const untilAlert = async (s) => { const w = s * 1000 - (Date.now() - tAlert); if (w > 0) await sleep(w); };
const plan = (await api(`/api/incidents/${inc.id}/agent`, { method: "POST" })).body?.analysis?.agent;
const step = (plan?.plan ?? []).find((s) => String(s.action).startsWith("LAB_"));
if (!step) throw new Error("agent proposed no lab step");
const prop = await api(`/api/incidents/${inc.id}/agent/propose/${step.rank}`, { method: "POST" });
events.proposed = `${step.action} ${step.target}`;

// beat 1: stay on Live attack while the alert and its pop-up are on screen
await untilAlert(8);

// beat 2: the incident page: why it was flagged, then the AI containment plan
await page.goto(`${BASE}/app/incidents/${inc.id}`);
await page.getByRole("heading", { name: "Why it was flagged" }).waitFor();
await sleep(3000);
await page.getByRole("heading", { name: "AI containment plan" }).scrollIntoViewIfNeeded().catch(() => {});
await sleep(5000);

// beat 3: back to the live view until the approval moment
await page.goto(`${BASE}/app/live-attack`);
await untilAlert(APPROVE_AFTER / 1000 - 3.5);

// beat 4: the admin approves on Approvals, at the recorded delay after the alert
await page.getByRole("link", { name: "Approvals" }).click();
const card = page.getByRole("article", { name: /Pending action/ }).filter({ hasText: inc.id });
await card.waitFor();
await sleep(1200);
await card.getByRole("button", { name: "Approve…" }).click();
await sleep(1500);
await untilAlert(APPROVE_AFTER / 1000);
await page.getByRole("dialog").getByRole("button", { name: "Approve and enforce" }).click();
events.approved_after_alert_s = (Date.now() - tAlert) / 1000;
await sleep(1200);
await page.getByRole("link", { name: "Live attack" }).click();

// 5. MOCK enforcer (a replay has no switch): report "applied" ~0.6 s later, as in live8
await new Promise((r) => setTimeout(r, 600));
const q = (await api("/api/lab/enforcement/queue")).body?.queue ?? [];
const item = q.find((x) => x.action_id === prop.body?.action_id) ?? q[0];
if (item) {
  await api("/api/lab/enforcement/report", {
    method: "POST",
    body: JSON.stringify({ action_id: item.action_id, state: "applied", detail: "MOCK enforcer (replay)", ts: Date.now() / 1000 }),
  });
}

while (Date.now() - t0 < DURATION) await new Promise((r) => setTimeout(r, 250));
shooting = false;
await shooter;
writeFileSync(join(FRAMES, "events.json"), JSON.stringify(events));
await browser.close();
