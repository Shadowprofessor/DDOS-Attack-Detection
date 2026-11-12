import { expect, test } from "@playwright/test";
import { ANALYST_KEY } from "./keys";

// v5.2.0: windows pushed through the real /api/live API (as scripts/live_bridge.py does) appear on the
// Live Attack view over /ws/live: L1 banner with the numbers, chart, top attackers, OVS counters,
// and the alert clears after quiet windows.
const H = { "X-API-Key": ANALYST_KEY };
const now = Math.floor(Date.now() / 1000);

const win = (i: number, pps: number) => ({
  start: now + i, end: now + i + 1, dst: "10.99.0.10", packets: pps, bytes: pps * 40, pps, bps: pps * 320,
  unique_src: 20, src_entropy: 4.32, proto_mix: pps ? { icmp: 0.99, tcp: 0.01 } : {}, tcp_flags: {},
  syn_rate: 0, conn_rate: 0, pkt_size: { mean: 84, p50: 84, p95: 84, max: 84 },
  top_talkers: pps ? [{ ip: "10.99.0.100", packets: Math.round(pps / 4) }, { ip: "10.99.0.101", packets: Math.round(pps / 5) }] : [],
  top_dst_ports: [],
});

test("live attack view: alert banner, chart, attackers and OVS appear live, then clear", async ({ page, request }) => {
  expect((await request.post("/api/live/reset", { headers: H })).status()).toBe(204);
  await page.goto("/app/");
  await page.getByLabel("API key").fill(ANALYST_KEY);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("link", { name: "Live attack" }).click();
  await expect(page.getByRole("heading", { name: "Live attack" })).toBeVisible();
  await expect(page.getByText("Stream live")).toBeVisible();
  await expect(page.getByText(/Waiting for live windows/)).toBeVisible();

  const post = (windows: object[]) => request.post("/api/live/windows", { headers: H, data: { sensor: "e2e", windows } });
  expect((await post([win(0, 30), win(1, 1416)])).status()).toBe(200);
  const banner = page.getByRole("alert");
  await expect(banner).toContainText("Attack in progress");
  await expect(banner).toContainText("10.99.0.10");
  await expect(banner).toContainText("ICMP 99%");
  await expect(banner).toContainText("1416.0 pps");
  // v5.3.0 explanation: what, detected by which layer, and why with the numbers
  await expect(banner).toContainText("ICMP flood");
  await expect(banner).toContainText("L1: 1,416 pps to 10.99.0.10 >= 500 pps critical threshold; ICMP 99% of packets; 20 sources -> 1 victim; T1498.001");
  await expect(page.getByRole("img", { name: /Packets per second.*current 1.4k pkt\/s/ })).toBeVisible();
  await expect(page.getByRole("cell", { name: "10.99.0.100" })).toBeVisible();

  const port = (rx: number) => ({ port: "s1-eth1", host: "attacker", rx_packets: rx, tx_packets: 0, rx_bytes: rx * 84, tx_bytes: 0 });
  await request.post("/api/live/ovs", { headers: H, data: { sensor: "e2e", switch: "s1", ts: now, ports: [port(0)] } });
  await request.post("/api/live/ovs", { headers: H, data: { sensor: "e2e", switch: "s1", ts: now + 2, ports: [port(2832)] } });
  await expect(page.getByRole("cell", { name: "s1/s1-eth1" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "1.4k pkt/s" })).toBeVisible();

  expect((await post([2, 3, 4, 5, 6].map((i) => win(i, 0)))).status()).toBe(200); // 5 quiet windows
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByText("No active L1 alert.")).toBeVisible();
  await expect(page.getByText(/cleared after/)).toBeVisible();
});
