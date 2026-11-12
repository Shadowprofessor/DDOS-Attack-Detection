// v5.2.0 Live Attack view: state model for /api/live/state + /ws/live events. Pure functions,
// unit-tested; the page only renders what these return.

export interface Talker { ip: string; packets: number }
export interface L1 { status: "NORMAL" | "WARNING" | "CRITICAL"; violation: boolean; rules: string[]; vector: string | null }
export interface LiveWindow {
  start: number; end: number; dst: string; packets: number; bytes: number; pps: number; bps: number;
  unique_src: number; src_entropy: number; proto_mix: Record<string, number>; tcp_flags: Record<string, number>;
  syn_rate: number; conn_rate: number; pkt_size: Record<string, number>; top_talkers: Talker[];
  top_dst_ports: { port: number; packets: number }[]; received_at: number; l1: L1; hint: string; sensor: string;
}
export interface Episode {
  id: string; dst: string; opened_at: number; window_start: number; status: string; vector: string | null;
  rules: string[]; hint: string; peak_pps: number; peak_bps: number; top_talkers: Talker[]; closed_at: number | null;
  explanation?: { detected_by: string; attack_type: string; confidence: number | null; mitre: string[]; reason: string } | null;
}
export interface OvsRate {
  switch: string; port: string; host?: string | null; ts: number; rx_packets: number; tx_packets: number;
  rx_dropped: number; tx_dropped: number; rx_pps: number | null; tx_pps: number | null;
}
export interface LiveFlow {
  src: string; dst: string; proto: number; dport: number; packets: number; final: boolean; label: string;
  is_attack: boolean; confidence: number | null; ood_suspected: boolean | null; received_at: number;
  basis?: "ml" | "multi_layer" | null; ml_label?: string | null;
}
export interface LiveSnapshot {
  server_time: number; victims: Record<string, LiveWindow[]>; open_alerts: Episode[]; episodes: Episode[];
  flows: LiveFlow[]; ovs: OvsRate[];
}
export interface Enforcement {
  action_id: string; state: string; target: string | null; action_type: string | null; victim_ip: string | null;
  ts: number | null; detail: string; approved_at: number | null;
}
export interface LiveModel {
  enforcement: Enforcement[];
  // Keyed by server-supplied strings: Maps (never plain objects) so a key like "__proto__" cannot
  // pollute a prototype, and keys must match a strict format before they are stored.
  victims: Map<string, LiveWindow[]>; open: Map<string, Episode>; episodes: Episode[];
  flows: LiveFlow[]; ovs: Map<string, OvsRate>;
}

export const KEEP_WINDOWS = 180;
const KEEP_EPISODES = 30;
const KEEP_FLOWS = 50;

export const empty = (): LiveModel => ({ victims: new Map(), open: new Map(), episodes: [], flows: [], ovs: new Map(), enforcement: [] });

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const PORT_KEY = /^[A-Za-z0-9_-]{1,32}\/[A-Za-z0-9_-]{1,16}$/;
export const isIp = (v: unknown): v is string => typeof v === "string" && IPV4.test(v);
const ovsKey = (r: OvsRate): string | null => {
  const k = `${r.switch}/${r.port}`;
  return PORT_KEY.test(k) ? k : null;
};

export function fromSnapshot(s: LiveSnapshot): LiveModel {
  const m = empty();
  for (const [dst, ws] of Object.entries(s.victims ?? {})) if (isIp(dst) && Array.isArray(ws)) m.victims.set(dst, ws.slice(-KEEP_WINDOWS));
  for (const e of s.open_alerts ?? []) if (isIp(e.dst)) m.open.set(e.dst, e);
  for (const r of s.ovs ?? []) {
    const k = ovsKey(r);
    if (k) m.ovs.set(k, r);
  }
  return { ...m, episodes: s.episodes ?? [], flows: s.flows ?? [], enforcement: m.enforcement };
}

type Ev = { type: string; [k: string]: unknown };

/** Apply one /ws/live event (immutably). Unknown events are ignored. */
export function applyEvent(m: LiveModel, ev: Ev): LiveModel {
  switch (ev.type) {
    case "live.window": {
      const w = ev.window as LiveWindow;
      if (!w || !isIp(w.dst)) return m;
      const victims = new Map(m.victims);
      victims.set(w.dst, [...(m.victims.get(w.dst) ?? []), w].slice(-KEEP_WINDOWS));
      return { ...m, victims };
    }
    case "live.alert": {
      const e = ev.episode as Episode;
      if (!e || !isIp(e.dst)) return m;
      const open = new Map(m.open);
      open.set(e.dst, e);
      return { ...m, open, episodes: [e, ...m.episodes.filter((x) => x.id !== e.id)].slice(0, KEEP_EPISODES) };
    }
    case "live.clear": {
      const e = ev.episode as Episode;
      if (!e) return m;
      const open = new Map(m.open);
      open.delete(e.dst);
      return { ...m, open, episodes: m.episodes.map((x) => (x.id === e.id ? e : x)) };
    }
    case "live.flow":
      return { ...m, flows: [ev.flow as LiveFlow, ...m.flows].slice(0, KEEP_FLOWS) };
    case "live.ovs": {
      const ovs = new Map(m.ovs);
      for (const r of (ev.ports as OvsRate[]) ?? []) {
        const k = ovsKey(r);
        if (k) ovs.set(k, r);
      }
      return { ...m, ovs };
    }
    case "live.enforcement":  // v5.4.0: what the lab enforcer did with an APPROVED action
      return { ...m, enforcement: [ev as unknown as Enforcement, ...m.enforcement].slice(0, 30) };
    case "live.reset":
      return empty();
    default:
      return m;
  }
}

/** Victim to show by default: one with an open alert, else the busiest in its latest window. */
export function pickVictim(m: LiveModel, current: string | null): string | null {
  if (current && m.victims.has(current)) return current;
  const open = [...m.open.keys()];
  if (open.length) return open[0] ?? null;
  let best: string | null = null;
  let bestPps = -1;
  for (const [dst, ws] of m.victims) {
    const last = ws[ws.length - 1];
    if (last && last.pps > bestPps) { best = dst; bestPps = last.pps; }
  }
  return best;
}

/** SVG polyline points for a series over the last `span` seconds (x: time, y: value, auto-scaled). */
export function seriesPoints(ws: LiveWindow[], key: "pps" | "bps", width: number, height: number, span = 120): { points: string; max: number } {
  const lastW = ws[ws.length - 1];
  if (!lastW) return { points: "", max: 0 };
  const tEnd = lastW.end;
  const tStart = tEnd - span;
  const shown = ws.filter((w) => w.end > tStart);
  const max = Math.max(1, ...shown.map((w) => w[key]));
  const pts = shown.map((w) => {
    const x = ((w.end - tStart) / span) * width;
    const y = height - (w[key] / max) * (height - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return { points: pts.join(" "), max };
}

export function fmtRate(v: number | null | undefined, unit: "pps" | "bps"): string {
  if (v === null || v === undefined) return "—";
  if (unit === "bps") {
    if (v >= 1e9) return `${(v / 1e9).toFixed(2)} Gb/s`;
    if (v >= 1e6) return `${(v / 1e6).toFixed(2)} Mb/s`;
    if (v >= 1e3) return `${(v / 1e3).toFixed(1)} kb/s`;
    return `${v.toFixed(0)} b/s`;
  }
  return v >= 1e3 ? `${(v / 1e3).toFixed(1)}k pkt/s` : `${v.toFixed(0)} pkt/s`;
}

/** Talkers summed over the last n windows (the per-window list is only a top-5). */
export function topTalkers(ws: LiveWindow[], n = 10, last = 10): Talker[] {
  const acc = new Map<string, number>();
  for (const w of ws.slice(-last)) for (const t of w.top_talkers ?? []) acc.set(t.ip, (acc.get(t.ip) ?? 0) + t.packets);
  return [...acc.entries()].map(([ip, packets]) => ({ ip, packets })).sort((a, b) => b.packets - a.packets).slice(0, n);
}
