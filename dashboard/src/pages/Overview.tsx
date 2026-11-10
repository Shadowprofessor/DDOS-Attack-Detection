import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api, type Overview } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatDuration, formatPercent, formatTime, severityTone } from "../lib/format";

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="card stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="muted small">{hint}</div>}
    </div>
  );
}

/** Bars drawn with SVG attributes (not inline styles) so the strict CSP holds. */
function SeverityBars({ counts }: { counts: Record<string, number> }) {
  const sevs = [5, 4, 3, 2, 1];
  const max = Math.max(1, ...sevs.map((s) => counts[String(s)] ?? 0));
  return (
    <svg className="bars" viewBox="0 0 300 130" role="img" aria-label="Open incidents by severity">
      {sevs.map((s, i) => {
        const n = counts[String(s)] ?? 0;
        const w = Math.round((n / max) * 220);
        return (
          <g key={s} transform={`translate(0 ${i * 26})`}>
            <text x="0" y="15" className="bar-label">
              Sev {s}
            </text>
            <rect x="48" y="3" width={Math.max(w, 2)} height="16" rx="3" className={`bar bar-${severityTone(s)}`} />
            <text x={56 + w} y="15" className="bar-value">
              {n}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export function OverviewPage() {
  const q = useQuery({ queryKey: ["overview"], queryFn: () => api<Overview>("/api/overview"), refetchInterval: 10_000 });

  if (q.isPending) return <p className="muted">Loading overview…</p>;
  if (q.isError) return <p role="alert" className="error">Could not load the overview.</p>;
  const o = q.data;

  return (
    <section aria-labelledby="ov-title">
      <h1 id="ov-title">Overview</h1>
      <div className="grid stats">
        <Stat label="Open incidents" value={String(o.incidents.open)} />
        <Stat label="Pending approvals" value={o.pending_actions === null ? "—" : String(o.pending_actions)} />
        <Stat label="Mean time to contain" value={formatDuration(o.kpis.mttc_seconds_avg)} />
        <Stat label="False-positive rate" value={formatPercent(o.kpis.false_positive_rate)}
              hint={`last ${o.incidents.sample_size} incidents`} />
      </div>

      <div className="grid two">
        <div className="card">
          <h2>Open by severity</h2>
          <SeverityBars counts={o.incidents.by_severity_open} />
        </div>

        <div className="card">
          <h2>CERT-In reporting timers</h2>
          {o.cert_in_timers.length === 0 ? (
            <p className="muted">No incidents awaiting a CERT-In report.</p>
          ) : (
            <ul className="timers">
              {o.cert_in_timers.map((t) => (
                <li key={t.incident_id} className={t.seconds_remaining < 900 ? "timer urgent" : "timer"}>
                  <Link to={`/incidents?focus=${encodeURIComponent(t.incident_id)}`}>{t.incident_id}</Link>
                  <span className="muted">{t.title}</span>
                  <span className="countdown">{formatDuration(t.seconds_remaining)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="grid two">
        <div className="card">
          <h2>Recent incidents</h2>
          <ul className="recent">
            {o.incidents.recent.map((i) => (
              <li key={i.id}>
                <SeverityBadge severity={i.severity} />
                <span className="mono">{i.id}</span>
                <span>{i.title}</span>
                <span className="muted small">{formatTime(i.detected_at)}</span>
              </li>
            ))}
            {o.incidents.recent.length === 0 && <li className="muted">No incidents yet.</li>}
          </ul>
        </div>
        <div className="card">
          <h2>Health</h2>
          <dl className="kv">
            <dt>ML models</dt>
            <dd className={o.health.models_loaded ? "ok" : "warn"}>{o.health.models_loaded ? "loaded" : "fallback"}</dd>
            <dt>AI analyst</dt>
            <dd className={o.health.llm.configured ? "ok" : "warn"}>
              {o.health.llm.configured ? "LLM configured" : "rule-based only"}
            </dd>
            <dt>Model chain</dt>
            <dd className="mono small">{o.health.llm.models.join(" → ") || "—"}</dd>
            <dt>Live clients</dt>
            <dd>{o.health.ws_clients}</dd>
          </dl>
        </div>
      </div>
      <p className="muted small">Updated {formatTime(o.generated_at)}</p>
    </section>
  );
}
