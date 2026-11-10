import { useState, type FormEvent } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, ApiError, json, type IncidentDetail, type IncidentPage } from "../api/client";

interface ChatReply {
  response: string;
  authority: string;
  model?: string;
}

interface Turn {
  role: "you" | "assistant";
  text: string;
  meta?: string;
}

export function AnalystPage() {
  const list = useQuery({ queryKey: ["incidents", "for-chat"], queryFn: () => api<IncidentPage>("/api/incidents?limit=50&include_replay=true") });
  const [incidentId, setIncidentId] = useState("");
  const detail = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => api<IncidentDetail>(`/api/incidents/${encodeURIComponent(incidentId)}`),
    enabled: Boolean(incidentId),
  });
  const [msg, setMsg] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const ask = useMutation({
    mutationFn: (text: string) => api<ChatReply>("/api/chat", { method: "POST", body: json({ message: text }) }),
    onSuccess: (r) => setTurns((t) => [...t, { role: "assistant", text: r.response, meta: `${r.authority}${r.model ? ` · ${r.model}` : ""}` }]),
    onError: (e) => setTurns((t) => [...t, { role: "assistant", text: e instanceof ApiError ? e.message : "Request failed.", meta: "error" }]),
  });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const text = msg.trim();
    if (!text) return;
    const scoped = incidentId ? `[incident ${incidentId}] ${text}` : text;
    setTurns((t) => [...t, { role: "you", text }]);
    setMsg("");
    ask.mutate(scoped);
  };

  const a = detail.data?.analysis;
  return (
    <section aria-labelledby="an-h">
      <h1 id="an-h">AI analyst</h1>
      <p className="muted">
        Read-only assistant. It answers from telemetry and cannot approve, block or change anything. Requests to do so are refused.
      </p>
      <div className="grid two">
        <div className="card">
          <label className="field">
            Scope to incident (optional)
            <select value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
              <option value="">No incident (global telemetry)</option>
              {list.data?.items.map((i) => <option key={i.id} value={i.id}>{i.id} — {i.title}</option>)}
            </select>
          </label>
          {incidentId && (
            a ? (
              <dl className="kv small">
                <dt>Stored analysis</dt><dd>{a.analysis.attack_type}</dd>
                <dt>Source</dt><dd className="mono">{a.source}{a.cached ? " · cached" : ""}</dd>
                <dt>Degraded</dt><dd>{a.degraded ? (a.degraded_reason ?? "yes") : "no"}</dd>
                <dt>Policy corrections</dt><dd>{a.policy_violations?.length ?? 0}</dd>
                <dt>Suspicious telemetry</dt><dd>{a.suspicious_telemetry ?? 0}</dd>
              </dl>
            ) : <p className="muted small">No stored analysis for this incident yet (run it from the incident page).</p>
          )}
        </div>
        <div className="card chat">
          <ol className="turns" aria-live="polite" aria-label="Conversation">
            {turns.map((t, i) => (
              <li key={i} className={`turn turn-${t.role}`}>
                <span className="muted small">{t.role === "you" ? "You" : "Assistant"}{t.meta ? ` · ${t.meta}` : ""}</span>
                <p>{t.text}</p>
              </li>
            ))}
            {turns.length === 0 && <li className="muted">Ask about detections, campaigns or an incident.</li>}
          </ol>
          <form onSubmit={onSubmit} className="row">
            <label className="field grow">
              Question
              <input value={msg} onChange={(e) => setMsg(e.target.value)} maxLength={1000} />
            </label>
            <button type="submit" className="btn primary" disabled={!msg.trim() || ask.isPending}>
              {ask.isPending ? "Thinking…" : "Ask"}
            </button>
          </form>
        </div>
      </div>
    </section>
  );
}
