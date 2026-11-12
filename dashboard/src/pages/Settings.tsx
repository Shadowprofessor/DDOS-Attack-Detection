import { Fragment, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { notificationsSupported, prefs, requestNotifications, setPrefs, type SocAlert } from "../alerts/alerts";
import { isAdmin, useAuth } from "../auth/store";
import { formatDuration, formatTime } from "../lib/format";

interface SystemInfo {
  version: string;
  environment: string;
  python: string;
  packages: Record<string, string | null>;
  models: { loaded: boolean; artifacts: { name: string; bytes: number; modified: number }[] };
  analyst: { base_url?: string; models?: string[]; timeout_s?: number; api_key_present?: boolean; prompt_version?: string; hash_ips?: boolean };
  incident_response: { rollback_ttl_s: number; rollback_max_attempts: number; cert_in_severity_threshold: number; cert_in_deadline_hours: number; cert_in_hash_iocs: boolean };
}

interface AlertsInfo {
  alerts: SocAlert[];
  webhook: { enabled: boolean; kind: string | null };
  dedupe_s: number;
  rate_per_min: number;
}

function AlertSettings() {
  const auth = useAuth();
  const [p, setP] = useState(prefs);
  const [perm, setPerm] = useState<string>(notificationsSupported() ? Notification.permission : "unsupported");
  const q = useQuery({ queryKey: ["alerts"], queryFn: () => api<AlertsInfo>("/api/alerts?limit=10"), refetchInterval: 30_000 });
  const test = useMutation({ mutationFn: () => api<{ sent: boolean }>("/api/alerts/test", { method: "POST" }) });
  return (
    <div className="card">
      <h2>Alerts</h2>
      <p className="muted small">
        Toasts appear on every page. Sound: 3 beeps critical, 2 high, 1 medium. These settings last until you reload the page.
      </p>
      <div className="row">
        <label>
          <input type="checkbox" checked={p.sound} onChange={(e) => setP(setPrefs({ sound: e.target.checked }))} /> Sound
        </label>
        <button
          type="button"
          className="btn"
          disabled={perm === "unsupported" || perm === "denied"}
          onClick={async () => {
            const r = await requestNotifications();
            setPerm(r);
            setP(prefs());
          }}
        >
          {perm === "granted" ? (p.notify ? "Browser notifications on" : "Turn on browser notifications") : perm === "denied" ? "Notifications blocked in this browser" : perm === "unsupported" ? "Notifications not supported" : "Allow browser notifications"}
        </button>
        {perm === "granted" && p.notify && (
          <button type="button" className="btn ghost" onClick={() => setP(setPrefs({ notify: false }))}>Turn off</button>
        )}
        {isAdmin(auth) && (
          <button type="button" className="btn" onClick={() => test.mutate()} disabled={test.isPending}>
            Send test alert
          </button>
        )}
      </div>
      {test.data && <p role="status" className="small">{test.data.sent ? "Test alert sent." : "Held back by dedupe / rate limit (try again in 2 min)."}</p>}
      {q.data && (
        <>
          <dl className="kv">
            <dt>Webhook</dt><dd>{q.data.webhook.enabled ? `on (${q.data.webhook.kind})` : "off (set DDOS_ALERT_WEBHOOK_URL)"}</dd>
            <dt>Dedupe</dt><dd>same alert at most once per {formatDuration(q.data.dedupe_s)}</dd>
            <dt>Rate limit</dt><dd>{q.data.rate_per_min} per minute (a CERT-In breach always goes through)</dd>
          </dl>
          <h3 className="small">Recent alerts</h3>
          <ul className="alert-list" aria-label="Recent alerts">
            {q.data.alerts.length === 0 && <li className="muted small">None yet.</li>}
            {q.data.alerts.map((a) => (
              <li key={a.id} className="small">
                <span className={`sev sev-${a.level === "info" ? "low" : a.level}`}>{a.level}</span>
                <span>{a.title}</span>
                <span className="muted">{formatTime(a.ts)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

const mb = (b: number) => `${(b / 1_048_576).toFixed(1)} MB`;

export function SettingsPage() {
  const q = useQuery({ queryKey: ["system"], queryFn: () => api<SystemInfo>("/api/system"), refetchInterval: 60_000 });
  if (q.isPending) return <p className="muted">Loading…</p>;
  if (q.isError) return <p role="alert" className="error">Could not load system info.</p>;
  const s = q.data;
  return (
    <section aria-labelledby="st-h">
      <h1 id="st-h">Settings &amp; health</h1>
      <p className="muted small">Read-only. Secrets are never sent to the browser; configuration changes go through the environment YAML / env vars.</p>
      <div className="grid two">
        <AlertSettings />
        <div className="card">
          <h2>Platform</h2>
          <dl className="kv">
            <dt>Release</dt><dd>v{s.version}</dd>
            <dt>Environment</dt><dd>{s.environment}</dd>
            <dt>Python</dt><dd>{s.python}</dd>
            {Object.entries(s.packages).map(([k, v]) => (
              <Fragment key={k}><dt>{k}</dt><dd className="mono small">{v ?? "not installed"}</dd></Fragment>
            ))}
          </dl>
        </div>
        <div className="card">
          <h2>AI analyst</h2>
          <dl className="kv">
            <dt>Model chain</dt><dd className="mono small">{(s.analyst.models ?? []).join(" → ") || "—"}</dd>
            <dt>API key</dt><dd className={s.analyst.api_key_present ? "ok" : "warn"}>{s.analyst.api_key_present ? "configured" : "not set (rule-based only)"}</dd>
            <dt>Timeout</dt><dd>{s.analyst.timeout_s ?? "—"} s</dd>
            <dt>Prompt</dt><dd className="mono small">{s.analyst.prompt_version ?? "—"}</dd>
            <dt>IP pseudonymisation</dt><dd>{s.analyst.hash_ips ? "on" : "off"}</dd>
          </dl>
        </div>
        <div className="card">
          <h2>Incident response</h2>
          <dl className="kv">
            <dt>Auto-rollback TTL</dt><dd>{formatDuration(s.incident_response.rollback_ttl_s)}</dd>
            <dt>Rollback retries</dt><dd>{s.incident_response.rollback_max_attempts}</dd>
            <dt>CERT-In threshold</dt><dd>severity ≥ {s.incident_response.cert_in_severity_threshold}</dd>
            <dt>CERT-In deadline</dt><dd>{s.incident_response.cert_in_deadline_hours} h</dd>
            <dt>Hash IOCs in draft</dt><dd>{s.incident_response.cert_in_hash_iocs ? "yes" : "no"}</dd>
          </dl>
        </div>
        <div className="card">
          <h2>Model artifacts {s.models.loaded ? <span className="ok small">loaded</span> : <span className="warn small">fallback</span>}</h2>
          <div className="table-wrap">
            <table className="incidents">
              <thead><tr><th scope="col">File</th><th scope="col">Size</th><th scope="col">Modified</th></tr></thead>
              <tbody>
                {s.models.artifacts.map((m) => (
                  <tr key={m.name}><td className="mono small">{m.name}</td><td>{mb(m.bytes)}</td><td className="small">{formatTime(m.modified)}</td></tr>
                ))}
                {s.models.artifacts.length === 0 && <tr><td colSpan={3} className="muted">No artifacts present (CI / fresh clone).</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  );
}
