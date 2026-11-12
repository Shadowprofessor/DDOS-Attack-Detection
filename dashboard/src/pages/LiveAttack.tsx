import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api, type IncidentPage } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import {
  applyEvent, empty, fmtRate, fromSnapshot, pickVictim, seriesPoints, topTalkers,
  type LiveModel, type LiveSnapshot,
} from "../live/liveModel";

// v5.2.0 Live Attack view: lab windows pushed by scripts/live_bridge.py, L1-evaluated on the server,
// streamed over /ws/live (session cookie, same origin, server -> client only).

const W = 640;
const H = 150;

function Chart({ ws, k, label }: { ws: Array<{ end: number; pps: number; bps?: number }>; k: "pps" | "bps"; label: string }) {
  const { points, max } = seriesPoints(ws, k, W, H);
  const lastW = ws[ws.length - 1];
  const last = lastW ? { pps: lastW.pps, bps: lastW.bps ?? 0 } : undefined;
  return (
    <figure className="chart">
      <figcaption>
        <span>{label}</span>
        <span className="mono">now {fmtRate(last?.[k], k)} · peak in view {fmtRate(max, k)}</span>
      </figcaption>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${label}, last 120 seconds; current ${fmtRate(last?.[k], k)}`}
        preserveAspectRatio="none">
        <line x1="0" y1={H - 1} x2={W} y2={H - 1} className="axis" />
        {points && <polyline points={points} className={`series series-${k}`} fill="none" />}
      </svg>
    </figure>
  );
}

function Mix({ title, data }: { title: string; data: Record<string, number> }) {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]);
  return (
    <div>
      <h3>{title}</h3>
      {rows.length === 0 ? <p className="muted small">none</p> : (
        <dl className="mix">
          {rows.map(([k, v]) => (
            <div key={k}>
              <dt>{k.toUpperCase().replace("_", "-")}</dt>
              <dd><meter min={0} max={1} value={v} aria-label={`${k} ${Math.round(v * 100)}%`} /> {Math.round(v * 100)}%</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

export function LiveAttackPage() {
  const [model, setModel] = useState<LiveModel>(empty);
  const [status, setStatus] = useState<"connecting" | "live" | "offline">("connecting");
  const [victim, setVictim] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now() / 1000);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    const connect = () => {
      setStatus("connecting");
      ws = new WebSocket(`${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws/live`);
      ws.onmessage = (m) => {
        let ev: { type: string; [k: string]: unknown };
        try {
          ev = JSON.parse(String(m.data));
        } catch {
          return;
        }
        if (ev.type === "auth_ok") {
          attempt = 0;
          setStatus("live");
          // (re)load the snapshot after subscribing, so nothing between the two is lost for long
          api<LiveSnapshot>("/api/live/state").then((s) => setModel(fromSnapshot(s))).catch(() => undefined);
          return;
        }
        setModel((prev) => applyEvent(prev, ev));
      };
      ws.onclose = () => {
        setStatus("offline");
        if (!closed) timer = setTimeout(connect, Math.min(30_000, 1000 * 2 ** Math.min(attempt++, 5)));
      };
    };
    connect();
    const tick = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      clearInterval(tick);
      ws?.close();
    };
  }, []);

  const incidents = useQuery({
    queryKey: ["incidents", "live"],
    queryFn: () => api<IncidentPage>("/api/incidents?limit=8&include_replay=false"),
    refetchInterval: 10_000,
  });

  const shown = pickVictim(model, victim);
  const ws = useMemo(() => (shown ? model.victims.get(shown) ?? [] : []), [model, shown]);
  const last = ws[ws.length - 1];
  const alert = shown ? model.open.get(shown) : undefined;
  const talkers = useMemo(() => topTalkers(ws), [ws]);
  const ovs = [...model.ovs.values()].sort((a, b) => a.port.localeCompare(b.port));
  const victims = [...model.victims.keys()].sort();

  return (
    <section aria-labelledby="la-h">
      <div className="row spread">
        <h1 id="la-h">Live attack</h1>
        <span className={`live live-${status}`} role="status">
          {status === "live" ? "Stream live" : status === "connecting" ? "Connecting…" : "Stream offline"}
        </span>
      </div>

      {alert ? (
        <div className={`banner banner-${alert.status === "CRITICAL" ? "critical" : "warn"}`} role="alert">
          <strong>{alert.status === "CRITICAL" ? "Attack in progress" : "Suspicious traffic"}:</strong>{" "}
          {alert.explanation?.attack_type ?? `L1 ${alert.vector ?? "rate anomaly"}`} toward <span className="mono">{alert.dst}</span> ·
          alert raised {Math.max(0, Math.round(now - alert.opened_at))} s ago · peak {fmtRate(alert.peak_pps, "pps")}
          {alert.explanation && (
            <p className="reason">
              <span className="muted small">Why ({alert.explanation.detected_by}
                {alert.explanation.mitre.length ? `, ${alert.explanation.mitre.join(", ")}` : ""}):</span>{" "}
              {alert.explanation.reason}
            </p>
          )}
          {alert.rules.length > 0 && <ul className="small">{alert.rules.map((r) => <li key={r}>{r}</li>)}</ul>}
        </div>
      ) : (
        <div className="banner banner-ok" role="status">
          {victims.length ? "No active L1 alert." : "Waiting for live windows… start scripts/live_bridge.py (see the runbook, block H)."}
        </div>
      )}

      {victims.length > 1 && (
        <label className="field">
          Victim
          <select value={shown ?? ""} onChange={(e) => setVictim(e.target.value)}>
            {victims.map((v) => <option key={v} value={v}>{v}{model.open.has(v) ? " (alert)" : ""}</option>)}
          </select>
        </label>
      )}

      {model.victimPort.length > 0 && (
        <div className="card">
          <h2>Delivered to the victim port (switch counters, ground truth)</h2>
          <Chart ws={model.victimPort} k="pps" label="Victim port packets per second (OVS)" />
          <p className="small muted">
            What the switch actually sent to the victim, sampled about every 2 s. Containment (MTTC) is measured from this.
            The capture-based chart below can under-count under load.
          </p>
        </div>
      )}

      <div className="card">
        <h2>Lab containment (human-approved)</h2>
        {model.enforcement.length === 0 ? (
          <p className="muted small">No containment yet. Rules appear here only after an admin approves a proposal on Approvals and the lab enforcer applies it.</p>
        ) : (
          <ul className="timeline">
            {model.enforcement.map((e, i) => (
              <li key={`${e.action_id}-${e.state}-${i}`}>
                <span className={`chip ${e.state === "applied" ? "ok" : e.state === "refused" || e.state === "failed" ? "warn" : ""}`}>{e.state}</span>
                <span className="mono">{e.action_type} {e.target}</span>
                <span className="muted small">{e.action_id}{e.approved_at && e.ts ? ` · ${Math.max(0, e.ts - e.approved_at).toFixed(1)} s after approval` : ""}</span>
                <span className="reason small">{e.detail}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="card">
        <h2>Traffic to {shown ? <span className="mono">{shown}</span> : "—"} (1 s windows, victim-side capture)</h2>
        <Chart ws={ws} k="pps" label="Packets per second" />
        <Chart ws={ws} k="bps" label="Bits per second" />
        {last && (
          <p className="small muted">
            Latest window: {last.packets.toLocaleString()} packets from {last.unique_src} sources (entropy {last.src_entropy.toFixed(2)}),
            SYN {last.syn_rate.toFixed(0)}/s, new connections {last.conn_rate.toFixed(0)}/s, mean size {last.pkt_size.mean ?? 0} B ·
            L1 <strong className={last.l1.violation ? "warn" : "ok"}>{last.l1.status}</strong>
          </p>
        )}
      </div>

      <div className="grid two">
        <div className="card">
          <h2>Top attackers (last 10 s)</h2>
          {talkers.length === 0 ? <p className="muted small">none</p> : (
            <table className="incidents"><thead><tr><th>Source</th><th>Packets</th></tr></thead>
              <tbody>{talkers.map((t) => <tr key={t.ip}><td className="mono">{t.ip}</td><td>{t.packets.toLocaleString()}</td></tr>)}</tbody>
            </table>
          )}
        </div>
        <div className="card">
          <h2>Protocol and TCP flag mix</h2>
          <Mix title="Protocols" data={last?.proto_mix ?? {}} />
          <Mix title="TCP flags (share of TCP packets)" data={last?.tcp_flags ?? {}} />
        </div>
      </div>

      <div className="grid two">
        <div className="card">
          <h2>Switch port counters (OVS)</h2>
          {ovs.length === 0 ? <p className="muted small">No OVS samples (start the demo with --ovs-poll).</p> : (
            <div className="table-wrap"><table className="incidents">
              <thead><tr><th>Port</th><th>Host</th><th>RX</th><th>TX</th><th>Dropped (rx/tx)</th></tr></thead>
              <tbody>{ovs.map((r) => (
                <tr key={`${r.switch}/${r.port}`}>
                  <td className="mono">{r.switch}/{r.port}</td><td>{r.host ?? "—"}</td>
                  <td>{fmtRate(r.rx_pps, "pps")}</td><td>{fmtRate(r.tx_pps, "pps")}</td>
                  <td>{r.rx_dropped}/{r.tx_dropped}</td>
                </tr>))}
              </tbody>
            </table></div>
          )}
        </div>
        <div className="card">
          <h2>Incidents</h2>
          {incidents.data?.items.length ? (
            <ul className="timeline">
              {incidents.data.items.map((i) => (
                <li key={i.id}><SeverityBadge severity={i.severity} /> <Link to={`/incidents/${i.id}`}>{i.id}</Link> <span>{i.title}</span></li>
              ))}
            </ul>
          ) : <p className="muted small">No incidents yet.</p>}
        </div>
      </div>

      <div className="card">
        <h2>Verdicts on sampled live flows (/score/flow)</h2>
        <p className="small muted">"Decided by" says whether the ML ensemble (L2) or the multi-layer rate corroboration made the call.
          During a flood, corroboration can flag benign flows to the same victim.</p>
        {model.flows.length === 0 ? <p className="muted small">none yet</p> : (
          <div className="table-wrap"><table className="incidents">
            <thead><tr><th>Flow</th><th>Verdict</th><th>Decided by</th><th>ML said</th><th>Confidence</th><th>OOD</th><th>Packets</th></tr></thead>
            <tbody>{model.flows.slice(0, 15).map((f, i) => (
              <tr key={`${f.src}-${f.dport}-${f.received_at}-${i}`}>
                <td className="mono">{f.src} → {f.dst}:{f.dport}</td>
                <td className={f.is_attack ? "warn" : ""}>{f.label}{f.final ? "" : " (running)"}</td>
                <td>{f.basis === "multi_layer" ? "rate corroboration" : f.basis === "ml" ? "ML (L2)" : "—"}</td>
                <td>{f.ml_label ?? "—"}</td>
                <td>{f.confidence === null ? "—" : f.confidence.toFixed(2)}</td>
                <td>{f.ood_suspected ? "yes" : "no"}</td><td>{f.packets}</td>
              </tr>))}
            </tbody>
          </table></div>
        )}
      </div>

      {model.episodes.length > 0 && (
        <div className="card">
          <h2>Alert history</h2>
          <ul className="timeline">
            {model.episodes.map((e) => (
              <li key={e.id}>
                <span className="mono small">{new Date(e.opened_at * 1000).toISOString().slice(11, 19)}</span>
                <span>{e.status}: {e.explanation?.attack_type ?? e.vector ?? "rate anomaly"} → {e.dst}</span>
                {e.explanation && <span className="reason small">{e.explanation.reason}</span>}
                <span className="muted small">{e.closed_at ? `cleared after ${Math.round(e.closed_at - e.opened_at)} s` : "active"}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
