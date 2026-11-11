import { describe, expect, it } from "vitest";
import { toItem, windowRange } from "./LiveFeed";

describe("live feed", () => {
  it("normalises broadcaster messages", () => {
    const f = toItem({ type: "flow_scored", timestamp: 1, flow: { label: "Syn", src_ip: "10.0.0.9", dst_ip: "10.0.0.4", is_attack: true, confidence: 0.97 } }, 1);
    expect(f).toMatchObject({ kind: "flow", label: "Syn", src: "10.0.0.9", attack: true, confidence: 0.97 });
    expect(toItem({ type: "dropped_packet", attacker_ip: "1.2.3.4", victim_ip: "10.0.0.4" }, 2)?.kind).toBe("dropped");
    expect(toItem({ type: "burst_alert", alert: { attack_type: "UDP", attacker_ip: "5.6.7.8" } }, 3)?.attack).toBe(true);
    expect(toItem({ type: "pending_update" }, 4)).toBeNull();
  });

  it("keeps the degraded-confidence flag and reason", () => {
    const f = toItem({ type: "flow_scored", flow: { label: "Syn", degraded_confidence: true,
      degradation_reason: "host_ingress: 23 backward features unobserved and zero-filled" } }, 6);
    expect(f?.degraded).toBe(true);
    expect(f?.degradationReason).toContain("host_ingress");
  });

  it("renders only a window of rows", () => {
    expect(windowRange(0, 360, 10_000)).toEqual({ start: 0, end: 18 });
    const w = windowRange(36_000, 360, 10_000);
    expect(w.end - w.start).toBeLessThan(40);
    expect(windowRange(0, 360, 5)).toEqual({ start: 0, end: 5 });
  });

  it("treats server strings as text, not markup", () => {
    const f = toItem({ type: "flow_scored", flow: { label: "<img src=x onerror=alert(1)>" } }, 5);
    expect(f?.label).toBe("<img src=x onerror=alert(1)>");
  });
});
