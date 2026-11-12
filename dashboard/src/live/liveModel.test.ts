import { describe, expect, it } from "vitest";
import { applyEvent, empty, fmtRate, fromSnapshot, pickVictim, seriesPoints, topTalkers, type LiveWindow } from "./liveModel";

const w = (start: number, pps: number, dst = "10.99.0.10", talkers = [{ ip: "10.99.0.100", packets: pps }]): LiveWindow => ({
  start, end: start + 1, dst, packets: pps, bytes: pps * 40, pps, bps: pps * 320, unique_src: 20, src_entropy: 4.3,
  proto_mix: { tcp: 1 }, tcp_flags: { syn: 1 }, syn_rate: pps, conn_rate: pps, pkt_size: { mean: 40 },
  top_talkers: talkers, top_dst_ports: [], received_at: start + 1.2,
  l1: { status: pps > 500 ? "CRITICAL" : "NORMAL", violation: pps > 500, rules: [], vector: null }, hint: "TCP 100%", sensor: "s",
});
const ep = { id: "live-1", dst: "10.99.0.10", opened_at: 5, window_start: 2, status: "CRITICAL", vector: "Rate-Based SYN Flood",
  rules: ["CRITICAL: Packet Rate"], hint: "TCP 100%", peak_pps: 1500, peak_bps: 1, top_talkers: [], closed_at: null };

describe("live model", () => {
  it("applies window, alert, clear, flow, ovs and reset events", () => {
    let m = empty();
    m = applyEvent(m, { type: "live.window", window: w(1, 20) });
    m = applyEvent(m, { type: "live.window", window: w(2, 1500) });
    m = applyEvent(m, { type: "live.alert", episode: ep });
    expect(m.victims.get("10.99.0.10")).toHaveLength(2);
    expect(m.open.get("10.99.0.10")?.id).toBe("live-1");
    m = applyEvent(m, { type: "live.clear", episode: { ...ep, closed_at: 20 } });
    expect(m.open.size).toBe(0);
    expect(m.episodes[0]?.closed_at).toBe(20);
    m = applyEvent(m, { type: "live.ovs", ports: [{ switch: "s1", port: "s1-eth1", ts: 1, rx_packets: 1, tx_packets: 1, rx_dropped: 0, tx_dropped: 0, rx_pps: 10, tx_pps: 1 }] });
    expect(m.ovs.get("s1/s1-eth1")?.rx_pps).toBe(10);
    m = applyEvent(m, { type: "nonsense" });
    expect(applyEvent(m, { type: "live.reset" })).toEqual(empty());
  });

  it("keeps a bounded history", () => {
    let m = empty();
    for (let i = 0; i < 400; i++) m = applyEvent(m, { type: "live.window", window: w(i, 1) });
    expect(m.victims.get("10.99.0.10")).toHaveLength(180);
  });

  it("picks the alerting victim, else the busiest, and respects a user choice", () => {
    const m = fromSnapshot({ server_time: 0, victims: { "10.99.0.10": [w(1, 5)], "10.99.0.11": [w(1, 50, "10.99.0.11")] },
      open_alerts: [], episodes: [], flows: [], ovs: [] });
    expect(pickVictim(m, null)).toBe("10.99.0.11");
    expect(pickVictim({ ...m, open: new Map([["10.99.0.10", ep]]) }, null)).toBe("10.99.0.10");
    expect(pickVictim(m, "10.99.0.10")).toBe("10.99.0.10");
    expect(pickVictim(empty(), null)).toBeNull();
  });

  it("builds chart points scaled to the max in view", () => {
    const { points, max } = seriesPoints([w(0, 0), w(1, 100), w(2, 50)], "pps", 120, 100, 3);
    expect(max).toBe(100);
    expect(points.split(" ")).toEqual(["40.0,98.0", "80.0,2.0", "120.0,50.0"]);
    expect(seriesPoints([], "pps", 1, 1).points).toBe("");
  });

  it("formats rates and sums talkers", () => {
    expect(fmtRate(1416, "pps")).toBe("1.4k pkt/s");
    expect(fmtRate(2_500_000, "bps")).toBe("2.50 Mb/s");
    expect(fmtRate(null, "pps")).toBe("—");
    const t = topTalkers([w(1, 10, "x", [{ ip: "a", packets: 3 }, { ip: "b", packets: 9 }]), w(2, 10, "x", [{ ip: "a", packets: 8 }])]);
    expect(t).toEqual([{ ip: "a", packets: 11 }, { ip: "b", packets: 9 }]);
  });

  it("ignores keys that are not IPs or port names (no prototype pollution)", () => {
    let m = empty();
    m = applyEvent(m, { type: "live.window", window: { ...w(1, 9), dst: "__proto__" } });
    m = applyEvent(m, { type: "live.alert", episode: { ...ep, dst: "constructor" } });
    m = applyEvent(m, { type: "live.ovs", ports: [{ switch: "__proto__", port: "x/../y", ts: 1, rx_packets: 0, tx_packets: 0, rx_dropped: 0, tx_dropped: 0, rx_pps: 1, tx_pps: 1 }] });
    expect(m.victims.size + m.open.size + m.ovs.size).toBe(0);
    expect(({} as Record<string, unknown>).pps).toBeUndefined();
    const s = fromSnapshot({ server_time: 0, victims: { "__proto__": [w(1, 1)] } as never, open_alerts: [], episodes: [], flows: [], ovs: [] });
    expect(s.victims.size).toBe(0);
  });

  it("records lab enforcement events", () => {
    const m = applyEvent(empty(), { type: "live.enforcement", action_id: "a1", state: "applied", target: "10.99.0.105",
      action_type: "LAB_OVS_DROP", victim_ip: "10.99.0.10", ts: 12, detail: "drop", approved_at: 10 });
    expect(m.enforcement[0]?.state).toBe("applied");
    expect(applyEvent(m, { type: "live.reset" }).enforcement).toEqual([]);
  });
});
