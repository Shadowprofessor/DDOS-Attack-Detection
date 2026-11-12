import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import {
  ANALYST_TRANSITIONS, api, ApiError, json, type AgentPlan, type AnalysisResult, type Explanation, type IncidentDetail, type Playbook,
} from "../api/client";
import { isAdmin, useAuth } from "../auth/store";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatDuration, formatTime } from "../lib/format";

const label = (s: string) => s.replace(/_/g, " ");

function errText(e: unknown): string {
  return e instanceof ApiError ? e.message : "Request failed.";
}

function detailText(d: Record<string, unknown>): string {
  return Object.entries(d)
    .map(([k, v]) => `${k}: ${typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

/** v5.3.0: what detected it, what it is, and why, with the numbers (live L1 alert + analyst). */
function WhyFlagged({ items }: { items: Explanation[] }) {
  if (!items.length) return null;
  return (
    <div className="card why" aria-labelledby="why-h">
      <h2 id="why-h">Why it was flagged</h2>
      <ul className="timeline">
        {items.map((x, i) => (
          <li key={i}>
            <strong>{x.detected_by}</strong>
            <span>{x.attack_type}</span>
            <span className="muted small">
              {x.confidence === null || x.confidence === undefined ? "rule (no probability)" : `confidence ${x.confidence.toFixed(2)}`}
              {x.mitre.length ? ` · ${x.mitre.join(", ")}` : ""}
            </span>
            <span className="reason">{x.reason}</span>
            {x.evidence?.filter((e) => e.startsWith("Rule analyst on the same data")).map((e) => (
              <span key={e} className="reason small muted">{e}</span>
            ))}
          </li>
        ))}
      </ul>
    </div>
  );
}

function whyItems(inc: IncidentDetail): Explanation[] {
  const hist = ((inc.aggregate ?? {}) as { alert_history?: { layer?: string; rule?: string; detail?: string }[] }).alert_history ?? [];
  const out: Explanation[] = hist.map((h) => ({ detected_by: `${h.layer ?? "?"} alert`, attack_type: h.rule ?? "—", confidence: null, mitre: [], reason: h.detail ?? "" }));
  if (inc.analysis?.explanation) out.push(inc.analysis.explanation);
  return out;
}

/** v5.4.0: the agent's ranked containment plan. A lab step can be PROPOSED here; an admin approves it. */
function AgentPlanPanel({ plan, onPropose, busy }: { plan: AgentPlan; onPropose: (rank: number) => void; busy: boolean }) {
  return (
    <div className="ai">
      <p className="ai-label">
        Agent plan ({plan.source}{plan.latency_ms ? `, ${Math.round(plan.latency_ms)} ms` : ""}) — recommendations only.
        Proposing a step creates a PENDING action; an admin must approve it on Approvals.
      </p>
      <dl className="kv">
        <dt>Assessed attack</dt><dd>{plan.attack_type} <span className="muted small">(confidence {plan.confidence.toFixed(2)}{plan.mitre_ids.length ? ` · ${plan.mitre_ids.join(", ")}` : ""})</span></dd>
        <dt>Why</dt><dd className="reason">{plan.reason}</dd>
        <dt>False positive?</dt><dd>{plan.false_positive_assessment}</dd>
        <dt>Tools used</dt><dd className="mono small">{plan.tool_trace.map((t) => t.tool).join(" → ") || "rules (no LLM)"}</dd>
      </dl>
      {plan.degraded_reason && <p className="muted small">Rule agent used: {plan.degraded_reason}</p>}
      {plan.policy_violations.length > 0 && (
        <p className="warn small">Policy removed: {plan.policy_violations.join("; ")}</p>
      )}
      <div className="table-wrap"><table className="incidents">
        <thead><tr><th>#</th><th>Action</th><th>Target</th><th>Blast radius</th><th>Reversible</th><th>TTL</th><th>Why</th><th></th></tr></thead>
        <tbody>{plan.plan.map((s) => (
          <tr key={s.rank}>
            <td>{s.rank}</td><td className="mono small">{s.action}</td><td className="mono">{s.target}</td>
            <td className={`blast-${s.blast_radius}`}>{s.blast_radius}</td><td>{s.reversible ? "yes" : "no"}</td>
            <td>{s.ttl_s} s</td><td className="small">{s.rationale}</td>
            <td>{s.action.startsWith("LAB_") ? (
              <button type="button" className="btn small" disabled={busy} onClick={() => onPropose(s.rank)}>Propose…</button>
            ) : <span className="muted small">advice</span>}</td>
          </tr>))}
        </tbody>
      </table></div>
      <h3>Evidence</h3>
      <ul>{plan.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul>
    </div>
  );
}

function AnalysisPanel({ result }: { result: AnalysisResult }) {
  const a = result.analysis;
  if (!a) return null;
  return (
    <div className="ai">
      <p className="ai-label">AI recommendation — review before acting. Nothing here has been executed.</p>
      <dl className="kv">
        <dt>Assessed attack</dt>
        <dd>{a.attack_type}</dd>
        <dt>MITRE ATT&amp;CK</dt>
        <dd className="mono">{a.mitre_ids.join(", ") || "—"}</dd>
        <dt>Suggested severity</dt>
        <dd>{a.severity}/5 (confidence {a.confidence.toFixed(2)})</dd>
        <dt>Source</dt>
        <dd className="mono small">
          {result.source}
          {result.cached ? " · cached" : ""}
          {result.degraded ? ` · degraded${result.degraded_reason ? `: ${result.degraded_reason}` : ""}` : ""}
        </dd>
        <dt>Safety</dt>
        <dd className="small">
          {result.policy_violations?.length ?? 0} output-policy corrections · {result.suspicious_telemetry ?? 0} instruction-like
          strings in telemetry
        </dd>
      </dl>
      <p>{a.report_summary}</p>
      <h3>Evidence</h3>
      <ul>{a.evidence.map((x, i) => <li key={i}>{x}</li>)}</ul>
      <h3>Recommended actions (not executed)</h3>
      <ul>
        {a.recommended_actions.map((r, i) => (
          <li key={i}>
            {r.action} <span className="muted small">· blast radius {r.blast_radius} · {r.reversible ? "reversible" : "irreversible"}</span>
          </li>
        ))}
        {a.recommended_actions.length === 0 && <li className="muted">None.</li>}
      </ul>
      <h3>False-positive assessment</h3>
      <p>{a.false_positive_assessment}</p>
      {a.next_queries.length > 0 && (
        <>
          <h3>Next queries</h3>
          <ul>{a.next_queries.map((q, i) => <li key={i}>{q}</li>)}</ul>
        </>
      )}
    </div>
  );
}

export function IncidentDetailPage() {
  const { id = "" } = useParams();
  const auth = useAuth();
  const admin = isAdmin(auth);
  const qc = useQueryClient();
  const key = ["incident", id];
  const q = useQuery({ queryKey: key, queryFn: () => api<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`), refetchInterval: 15_000 });
  const pbs = useQuery({ queryKey: ["playbooks"], queryFn: () => api<Record<string, Playbook>>("/api/playbooks"), staleTime: 300_000 });
  const [note, setNote] = useState("");
  const [pendingTo, setPendingTo] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [draft, setDraft] = useState<string | null>(null);
  const [ref, setRef] = useState("");

  const done = (text: string) => {
    setMsg({ ok: true, text });
    void qc.invalidateQueries({ queryKey: key });
    void qc.invalidateQueries({ queryKey: ["incidents"] });
    void qc.invalidateQueries({ queryKey: ["overview"] });
  };
  const fail = (e: unknown) => setMsg({ ok: false, text: errText(e) });
  const base = `/api/incidents/${encodeURIComponent(id)}`;

  const transition = useMutation({
    mutationFn: (v: { to: string; justification?: string }) => api(`${base}/transition`, { method: "POST", body: json(v) }),
    onSuccess: (_d, v) => done(`Moved to ${label(v.to)}.`),
    onError: fail,
  });
  const addNote = useMutation({
    mutationFn: (text: string) => api(`${base}/notes`, { method: "POST", body: json({ text }) }),
    onSuccess: () => {
      setNote("");
      done("Note added.");
    },
    onError: fail,
  });
  const runStep = useMutation({
    mutationFn: (v: { pb: string; step: string }) =>
      api(`${base}/playbook/${encodeURIComponent(v.pb)}/step/${encodeURIComponent(v.step)}`, { method: "POST", body: json({}) }),
    onSuccess: (_d, v) => {
      done(`Step "${label(v.step)}" recorded.`);
      void qc.invalidateQueries({ queryKey: ["approvals"] });
    },
    onError: fail,
  });
  const analyze = useMutation({
    mutationFn: () => api(`${base}/analyze`, { method: "POST" }),
    onSuccess: () => done("Analysis updated."),
    onError: fail,
  });
  const runAgent = useMutation({
    mutationFn: () => api(`${base}/agent`, { method: "POST" }),
    onSuccess: () => done("Agent plan updated."),
    onError: fail,
  });
  const proposeStep = useMutation({
    mutationFn: (rank: number) => api<{ action_id: string }>(`${base}/agent/propose/${rank}`, { method: "POST" }),
    onSuccess: (r) => {
      done(`Proposed ${r.action_id}: PENDING until an admin approves it on Approvals.`);
      void qc.invalidateQueries({ queryKey: ["approvals"] });
    },
    onError: fail,
  });
  const reported = useMutation({
    mutationFn: (reference: string) => api(`${base}/cert-in/reported`, { method: "POST", body: json({ reference }) }),
    onSuccess: () => {
      setRef("");
      done("CERT-In report recorded.");
    },
    onError: fail,
  });

  if (q.isPending) return <p className="muted">Loading incident…</p>;
  if (q.isError) return <p role="alert" className="error">{errText(q.error)}</p>;
  const inc = q.data;
  const transitions = inc.allowed_transitions.filter((t) => admin || ANALYST_TRANSITIONS.has(t));
  const doneSteps = new Set(inc.playbook_runs.map((r) => `${r.playbook_id}/${r.step}`));
  const agg = inc.aggregate as Record<string, unknown> | null;

  const loadDraft = async () => {
    try {
      setDraft(JSON.stringify(await api(`${base}/cert-in/draft`), null, 2));
    } catch (e) {
      fail(e);
    }
  };

  const onNote = (e: FormEvent) => {
    e.preventDefault();
    if (note.trim()) addNote.mutate(note.trim());
  };

  return (
    <section aria-labelledby="inc-h">
      <p><Link to="/incidents">← Incidents</Link></p>
      <header className="inc-head">
        <h1 id="inc-h">
          <span className="mono">{inc.id}</span> {inc.title}
        </h1>
        <div className="row">
          <SeverityBadge severity={inc.severity} />
          <span className={`status status-${inc.status}`}>{label(inc.status)}</span>
          <span className="muted small">CSF 2.0: {inc.csf_function}</span>
          <span className="muted small">{label(inc.attack_family)}</span>
          {inc.is_replay && <span className="tag">replay</span>}
          <span className={inc.chain.ok ? "chip ok" : "chip warn"}>
            Timeline {inc.chain.ok ? `verified (${inc.chain.events} events)` : `BROKEN at #${inc.chain.broken_at}`}
          </span>
        </div>
      </header>

      {msg && (
        <p role={msg.ok ? "status" : "alert"} className={msg.ok ? "ok" : "error"}>
          {msg.text}
        </p>
      )}

      <div className="grid two">
        <div className="card">
          <h2>Lifecycle</h2>
          <p className="small muted">Detected {formatTime(inc.detected_at)} · contained {formatTime(inc.contained_at)} · closed {formatTime(inc.closed_at)}</p>
          <div className="row">
            {transitions.map((t) => (
              <button key={t} type="button" className="btn" disabled={transition.isPending}
                onClick={() => (t === "contained" ? setPendingTo(t) : transition.mutate({ to: t }))}>
                Move to {label(t)}
              </button>
            ))}
            {transitions.length === 0 && <span className="muted small">No transitions available for your role.</span>}
          </div>
          <div className="row">
            <a className="btn" href={`${base}/export?format=md`} download>Export Markdown</a>
            <a className="btn" href={`${base}/export?format=pdf`} download>Export PDF</a>
          </div>
        </div>

        <div className="card">
          <h2>CERT-In</h2>
          {inc.cert_in_deadline === null ? (
            <p className="muted">Below the reporting threshold.</p>
          ) : inc.cert_in_reported_at ? (
            <p className="ok">Reported {formatTime(inc.cert_in_reported_at)}.</p>
          ) : (
            <p>
              Report due {formatTime(inc.cert_in_deadline)} — <strong className="countdown">{formatDuration(inc.cert_in_seconds_remaining)}</strong>
            </p>
          )}
          {admin && inc.cert_in_deadline !== null && (
            <>
              <div className="row">
                <button type="button" className="btn" onClick={loadDraft}>View report draft</button>
              </div>
              {!inc.cert_in_reported_at && (
                <form className="row" onSubmit={(e) => { e.preventDefault(); if (ref.trim().length >= 3) reported.mutate(ref.trim()); }}>
                  <label className="field">
                    CERT-In acknowledgement reference
                    <input value={ref} onChange={(e) => setRef(e.target.value)} maxLength={200} />
                  </label>
                  <button type="submit" className="btn" disabled={ref.trim().length < 3}>Mark reported</button>
                </form>
              )}
              {draft && <pre className="draft" aria-label="CERT-In report draft">{draft}</pre>}
            </>
          )}
        </div>
      </div>

      <WhyFlagged items={whyItems(inc)} />
      {agg && (
        <div className="card">
          <div className="row spread">
            <h2>AI containment plan</h2>
            <button type="button" className="btn" onClick={() => runAgent.mutate()} disabled={runAgent.isPending}>
              {runAgent.isPending ? "Agent working…" : inc.analysis?.agent ? "Re-run the agent" : "Ask the agent"}
            </button>
          </div>
          {inc.analysis?.agent ? (
            <AgentPlanPanel plan={inc.analysis.agent} onPropose={(r) => proposeStep.mutate(r)} busy={proposeStep.isPending} />
          ) : <p className="muted">No plan yet. The agent only reads data and recommends; it cannot block anything.</p>}
        </div>
      )}
      <div className="card">
        <div className="row spread">
          <h2>AI analyst</h2>
          {agg && (
            <button type="button" className="btn" onClick={() => analyze.mutate()} disabled={analyze.isPending}>
              {analyze.isPending ? "Analysing…" : inc.analysis?.analysis ? "Re-run analysis" : "Run analysis"}
            </button>
          )}
        </div>
        {inc.analysis?.analysis ? <AnalysisPanel result={inc.analysis} /> : <p className="muted">No analysis yet.</p>}
      </div>

      {agg && (
        <div className="card">
          <h2>Telemetry (aggregated)</h2>
          <dl className="kv">
            <dt>Packets/s</dt><dd>{String(agg.pps ?? "—")}</dd>
            <dt>Bits/s</dt><dd>{String(agg.bps ?? "—")}</dd>
            <dt>Unique sources</dt><dd>{String(agg.unique_src_ips ?? "—")}</dd>
            <dt>Top sources</dt>
            <dd className="mono small">{((agg.top_src_ips as { key: string; share: number }[] | undefined) ?? []).map((s) => `${s.key} (${(s.share * 100).toFixed(0)}%)`).join(", ") || "—"}</dd>
            <dt>Targets</dt><dd className="mono small">{((agg.dst_ips as string[] | undefined) ?? []).join(", ") || "—"}</dd>
          </dl>
        </div>
      )}

      <div className="card">
        <h2>Playbooks</h2>
        {inc.suggested_playbooks.length === 0 && <p className="muted">No playbook matches this attack family.</p>}
        {inc.suggested_playbooks.map((pid) => {
          const pb = pbs.data?.[pid];
          if (!pb) return <p key={pid} className="muted">{pid}</p>;
          return (
            <div key={pid} className="playbook">
              <h3>{pb.name} <span className="muted small mono">{pb.mitre.join(", ")}</span></h3>
              <ol>
                {pb.steps.map((s) => {
                  const ran = doneSteps.has(`${pid}/${s.id}`);
                  const allowed = admin || s.requires_role === "analyst";
                  return (
                    <li key={s.id} className={ran ? "step done" : "step"}>
                      <span>
                        {s.title} <span className="muted small">· {label(s.kind)}{s.requires_role === "admin" ? " · admin" : ""}</span>
                      </span>
                      {ran ? (
                        <span className="ok small">done</span>
                      ) : allowed ? (
                        <button type="button" className="btn small" disabled={runStep.isPending}
                          onClick={() => runStep.mutate({ pb: pid, step: s.id })}>
                          {s.kind === "propose_action" ? "Request action" : "Mark done"}
                        </button>
                      ) : null}
                    </li>
                  );
                })}
              </ol>
              <p className="muted small">"Request action" only proposes. An admin must approve it on the Approvals page.</p>
            </div>
          );
        })}
      </div>

      <div className="card">
        <h2>Mitigation actions</h2>
        {inc.actions.length === 0 ? <p className="muted">None linked.</p> : (
          <ul className="recent">
            {inc.actions.map((a) => (
              <li key={a.action_id}>
                <span className="mono">{a.action_id}</span>
                <span>{label(a.rollback_state)}</span>
                {a.rollback_at && a.rollback_state === "scheduled" && <span className="muted small">auto-rollback {formatTime(a.rollback_at)}</span>}
              </li>
            ))}
          </ul>
        )}
        <p className="small"><Link to="/approvals">Open approvals</Link></p>
      </div>

      <div className="card">
        <h2>Notes</h2>
        <form onSubmit={onNote} className="row">
          <label className="field grow">
            Add a note
            <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={4000} />
          </label>
          <button type="submit" className="btn" disabled={!note.trim() || addNote.isPending}>Add note</button>
        </form>
      </div>

      <div className="card">
        <h2>Timeline</h2>
        <ol className="timeline">
          {inc.events.map((e) => (
            <li key={e.seq}>
              <span className="muted small mono">#{e.seq} {formatTime(e.ts)}</span>
              <span className="mono small">{e.actor}</span>
              <strong>{label(e.kind)}</strong>
              <span className="small">{detailText(e.detail)}</span>
            </li>
          ))}
        </ol>
      </div>

      <ConfirmDialog
        open={pendingTo === "contained"}
        title="Mark as contained"
        confirmLabel="Mark contained"
        reasonLabel="Justification (required unless an approved action is linked)"
        onCancel={() => setPendingTo(null)}
        onConfirm={(reason) => {
          setPendingTo(null);
          transition.mutate(reason ? { to: "contained", justification: reason } : { to: "contained" });
        }}
      >
        <p>Containment needs at least one human-approved action, or a written justification.</p>
      </ConfirmDialog>
    </section>
  );
}
