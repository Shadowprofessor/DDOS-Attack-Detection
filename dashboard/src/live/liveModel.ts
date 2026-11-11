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
export interface LiveModel {
  victims: Record<string, LiveWindow[]>; open: Record<string, Episode>; episodes: Episode[];
  flows: LiveFlow[]; ovs: Record<string, OvsRate>;
}

export const KEEP_WINDOWS = 180;
const KEEP_EPISODES = 30;
const KEEP_FLOWS = 50;

export const empty = (): LiveModel => ({ victims: {}, open: {}, episodes: [], flows: [], ovs: {} });

export function fromSnapshot(s: LiveSnapshot): LiveModel {
  const ovs: Record<string, OvsRate> = {};
  for (const r of s.ovs ?? []) ovs[`${r.switch}/${r.port}`] = r;
  const open: Record<string, Episode> = {};
  for (const e of s.open_alerts ?? []) open[e.dst] = e;
  return { victims: s.victims ?? {}, open, episodes: s.episodes ?? [], flows: s.flows ?? [], ovs };
}

type Ev = { type: string; [k: string]: unknown };

/** Apply one /ws/live event (immutably). Unknown events are ignored. */
export function applyEvent(m: LiveModel, ev: Ev): LiveModel {
  switch (ev.type) {
    case "live.window": {
      const w = ev.window as LiveWindow;
      const prev = m.victims[w.dst] ?? [];
      return { ...m, victims: { ...m.victims, [w.dst]: [...prev, w].slice(-KEEP_WINDOWS) } };
    }
    case "live.alert": {
      const e = ev.episode as Episode;
      return { ...m, open: { ...m.open, [e.dst]: e }, episodes: [e, ...m.episodes.filter((x) => x.id !== e.id)].slice(0, KEEP_EPISODES) };
    }
    case "live.clear": {
      const e = ev.episode as Episode;
      const open = { ...m.open };
      delete open[e.dst];
      return { ...m, open, episodes: m.episodes.map((x) => (x.id === e.id ? e : x)) };
    }
    case "live.flow":
      return { ...m, flows: [ev.flow as LiveFlow, ...m.flows].slice(0, KEEP_FLOWS) };
    case "live.ovs": {
      const ovs = { ...m.ovs };
      for (const r of (ev.ports as OvsRate[]) ?? []) ovs[`${r.switch}/${r.port}`] = r;
      return { ...m, ovs };
    }
    case "live.reset":
      return empty();
    default:
      return m;
  }
}

/** Victim to show by default: one with an open alert, else the busiest in its latest window. */
export function pickVictim(m: LiveModel, current: string | null): string | null {
  if (current && m.victims[current]) return current;
  const open = Object.keys(m.open);
  if (open.length) return open[0] ?? null;
  let best: string | null = null;
  let bestPps = -1;
  for (const [dst, ws] of Object.entries(m.victims)) {
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
