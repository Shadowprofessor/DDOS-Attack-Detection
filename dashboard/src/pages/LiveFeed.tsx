import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

// Live flow / alert stream from /ws/dashboard (session cookie, same origin, server -> client only).
// The list is windowed: only the visible rows are in the DOM, so thousands of events stay cheap.

export interface FeedItem {
  id: number;
  ts: number;
  kind: "flow" | "alert" | "dropped" | "campaign";
  label: string;
  src: string;
  dst: string;
  attack: boolean;
  confidence: number | null;
}

const MAX_ITEMS = 2000;
const ROW_PX = 36;

type Raw = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" || typeof v === "number" ? String(v) : "");

/** Normalise one broadcaster message to a feed row (exported for unit tests). */
export function toItem(msg: Raw, id: number): FeedItem | null {
  const ts = typeof msg.timestamp === "number" ? msg.timestamp : Date.now() / 1000;
  switch (msg.type) {
    case "flow_scored": {
      const f = (msg.flow ?? {}) as Raw;
      return {
        id, ts, kind: "flow", label: str(f.label ?? f.attack_type ?? "flow"),
        src: str(f.src_ip), dst: str(f.dst_ip), attack: Boolean(f.is_attack),
        confidence: typeof f.confidence === "number" ? f.confidence : null,
      };
    }
    case "burst_alert": {
      const a = (msg.alert ?? {}) as Raw;
      return { id, ts, kind: "alert", label: str(a.attack_type ?? a.type ?? "burst alert"), src: str(a.attacker_ip ?? a.src_ip), dst: str(a.victim_ip ?? a.dst_ip), attack: true, confidence: null };
    }
    case "dropped_packet":
      return { id, ts, kind: "dropped", label: `dropped (${str(msg.status) || "DROPPED"})`, src: str(msg.attacker_ip), dst: str(msg.victim_ip), attack: true, confidence: null };
    case "campaign_detected":
      return { id, ts, kind: "campaign", label: "campaign detected", src: str((msg as Raw).campaign_id), dst: "", attack: true, confidence: null };
    default:
      return null;
  }
}

export function windowRange(scrollTop: number, viewport: number, total: number, rowPx = ROW_PX, overscan = 8) {
  const start = Math.max(0, Math.floor(scrollTop / rowPx) - overscan);
  const end = Math.min(total, Math.ceil((scrollTop + viewport) / rowPx) + overscan);
  return { start, end };
}

/** Sets an element's height through CSSOM (allowed by our CSP; no inline style attribute). */
function useHeightPx(ref: React.RefObject<HTMLElement | null>, px: number) {
  useLayoutEffect(() => {
    if (ref.current) ref.current.style.height = `${px}px`;
  }, [ref, px]);
}

export function LiveFeedPage() {
  const [items, setItems] = useState<FeedItem[]>([]);
  const [paused, setPaused] = useState(false);
  const [attacksOnly, setAttacksOnly] = useState(false);
  const [kind, setKind] = useState("");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<"connecting" | "live" | "offline">("connecting");
  const pausedRef = useRef(paused);
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);
  const buffered = useRef<FeedItem[]>([]);
  const [held, setHeld] = useState(0);
  const nextId = useRef(1);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    const connect = () => {
      setStatus("connecting");
      ws = new WebSocket(`${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws/dashboard`);
      ws.onmessage = (m) => {
        let msg: Raw;
        try {
          msg = JSON.parse(String(m.data)) as Raw;
        } catch {
          return;
        }
        if (msg.type === "auth_ok") {
          attempt = 0;
          setStatus("live");
          return;
        }
        const it = toItem(msg, nextId.current++);
        if (!it) return;
        if (pausedRef.current) {
          buffered.current.push(it);
          setHeld(buffered.current.length);
        }
        else setItems((prev) => [it, ...prev].slice(0, MAX_ITEMS));
      };
      ws.onclose = () => {
        setStatus("offline");
        if (!closed) timer = setTimeout(connect, Math.min(30_000, 1000 * 2 ** Math.min(attempt++, 5)));
      };
    };
    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, []);

  const resume = () => {
    const queued = buffered.current.reverse();
    buffered.current = [];
    setHeld(0);
    setItems((prev) => [...queued, ...prev].slice(0, MAX_ITEMS));
    setPaused(false);
  };

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return items.filter((i) => (!attacksOnly || i.attack) && (!kind || i.kind === kind) &&
      (!needle || `${i.src} ${i.dst} ${i.label}`.toLowerCase().includes(needle)));
  }, [items, attacksOnly, kind, q]);

  const viewportRef = useRef<HTMLDivElement>(null);
  const innerRef = useRef<HTMLDivElement>(null);
  const topRef = useRef<HTMLDivElement>(null);
  const [scroll, setScroll] = useState({ top: 0, h: 480 });
  const { start, end } = windowRange(scroll.top, scroll.h, shown.length);
  useHeightPx(innerRef, shown.length * ROW_PX);
  useHeightPx(topRef, start * ROW_PX);

  return (
    <section aria-labelledby="lf-h">
      <h1 id="lf-h">Live feed</h1>
      <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Filter live feed">
        <label>
          Event type
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">All</option>
            <option value="flow">Scored flows</option>
            <option value="alert">Burst alerts</option>
            <option value="dropped">Dropped (enforced)</option>
            <option value="campaign">Campaigns</option>
          </select>
        </label>
        <label>
          Search IP / label
          <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={64} />
        </label>
        <label className="check">
          <input type="checkbox" checked={attacksOnly} onChange={(e) => setAttacksOnly(e.target.checked)} />
          Attacks only
        </label>
        <button type="button" className="btn" onClick={() => (paused ? resume() : setPaused(true))} aria-pressed={paused}>
          {paused ? `Resume (${held} held)` : "Pause"}
        </button>
        <span className={`live live-${status}`} role="status">
          {status === "live" ? "Stream live" : status === "connecting" ? "Connecting…" : "Stream offline"}
        </span>
      </form>
      <p className="muted small" aria-live="polite">{shown.length} events shown (last {MAX_ITEMS} kept)</p>
      <div className="feed" ref={viewportRef} tabIndex={0} aria-label="Live events"
        onScroll={(e) => setScroll({ top: e.currentTarget.scrollTop, h: e.currentTarget.clientHeight })}>
        <div ref={innerRef} className="feed-inner" role="list">
          <div ref={topRef} aria-hidden="true" />
          {shown.slice(start, end).map((i) => (
            <div key={i.id} className={`feed-row ${i.attack ? "attack" : ""}`} role="listitem">
              <span className="mono small">{new Date(i.ts * 1000).toISOString().slice(11, 19)}</span>
              <span className={`kind kind-${i.kind}`}>{i.kind}</span>
              <span className="mono">{i.src || "—"} → {i.dst || "—"}</span>
              <span>{i.label}</span>
              <span className="muted small">{i.confidence === null ? "" : i.confidence.toFixed(2)}</span>
            </div>
          ))}
        </div>
        {shown.length === 0 && <p className="muted pad">Waiting for events… (score flows via <code>/score/flow</code> to see them here)</p>}
      </div>
    </section>
  );
}
