import { expect, test, type Page } from "@playwright/test";
// Runs after smoke/ux (alphabetical): it adds an incident, which would change their exact counts.
import { ADMIN_KEY, ANALYST_KEY } from "./keys";

// v5.4.0: agent plan -> analyst proposes a lab step (PENDING) -> admin approves -> the (mocked) lab
// enforcer reports "applied" -> the Live Attack view shows it. CI has no OVS: the enforcer is the
// report API it calls through the bridge.
const SYN_AGG = {
  incident_id: "e2e-cont", window_start: 1, pps: 1480, bps: 5e5, unique_src_ips: 50, dst_ips: ["10.99.0.10"],
  protocol_mix: { tcp: 1.0 }, tcp_flag_ratios: { syn: 0.5, rst: 0.5 }, tcp_payload_share: 0.0,
  top_src_ips: [{ key: "10.99.0.107", share: 0.05 }, { key: "10.99.0.108", share: 0.04 }],
};

async function loginAs(page: Page, key: string) {
  await page.goto("/app/");
  await page.getByLabel("API key").fill(key);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test("agent plan -> propose -> admin approves -> enforcer applies -> live view shows it", async ({ page, request }) => {
  const H = { "X-API-Key": ANALYST_KEY };
  // the agent prefers live windows over the stored aggregate: start from an empty live view
  expect((await request.post("/api/live/reset", { headers: H })).status()).toBe(204);
  const inc = await (await request.post("/api/incidents", { headers: H, data: { title: "E2E SYN flood for containment", severity: 4, aggregate: SYN_AGG } })).json();

  await loginAs(page, ANALYST_KEY);
  await page.goto(`/app/incidents/${inc.id}`);
  await page.getByRole("button", { name: "Ask the agent" }).click();
  const plan = page.getByRole("heading", { name: "AI containment plan" }).locator("../..");
  await expect(plan).toContainText("TCP SYN flood");
  await expect(plan).toContainText("recommendations only");
  const ipRow = plan.getByRole("row").filter({ hasText: "10.99.0.107" });
  await expect(ipRow).toContainText("LAB_OVS_DROP");
  await ipRow.getByRole("button", { name: "Propose…" }).click();
  await expect(page.getByRole("status").filter({ hasText: /PENDING until an admin approves/ })).toBeVisible();

  // the analyst cannot approve; the admin can
  await page.getByRole("button", { name: "Log out" }).click();
  await loginAs(page, ADMIN_KEY);
  await page.getByRole("link", { name: "Approvals" }).click();
  const card = page.getByRole("article", { name: /Pending action/ }).filter({ hasText: "10.99.0.107" });
  await expect(card).toContainText("LAB_OVS_DROP");
  await card.getByRole("button", { name: "Approve…" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Approve and enforce" }).click();
  await expect(page.getByRole("status").filter({ hasText: /Approve: .* done/ })).toBeVisible();

  // approved -> queued for the lab enforcer; the mocked enforcer applies and reports
  const queue = await (await request.get("/api/lab/enforcement/queue", { headers: H })).json();
  const item = queue.queue.find((q: { target: string }) => q.target === "10.99.0.107");
  expect(item.op).toBe("apply");
  await page.goto("/app/live-attack");
  await expect(page.getByText("Stream live")).toBeVisible();
  const rep = await request.post("/api/lab/enforcement/report", {
    headers: H, data: { action_id: item.action_id, state: "applied", detail: "drop rule installed (mock enforcer)", ts: Date.now() / 1000 },
  });
  expect(rep.status()).toBe(200);
  const lab = page.getByRole("heading", { name: "Lab containment (human-approved)" }).locator("..");
  await expect(lab).toContainText("applied");
  await expect(lab).toContainText("LAB_OVS_DROP 10.99.0.107");
});
