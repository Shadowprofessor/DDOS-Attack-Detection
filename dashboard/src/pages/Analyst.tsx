import { useState, type FormEvent } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, ApiError, json, type IncidentDetail, type IncidentPage } from "../api/client";
import { Markdown } from "../components/Markdown";

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
    mutationFn: (v: { text: string; history: { role: "user" | "assistant"; text: string }[] }) =>
      api<ChatReply>("/api/chat", { method: "POST", body: json({ message: v.text, history: v.history, incident_id: incidentId || undefined }) }),
    onSuccess: (r) => setTurns((t) => [...t, { role: "assistant", text: r.response, meta: `${r.authority}${r.model ? ` · ${r.model}` : ""}` }]),
    onError: (e) => setTurns((t) => [...t, { role: "assistant", text: e instanceof ApiError ? e.message : "Request failed.", meta: "error" }]),
  });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const text = msg.trim();
    if (!text) return;
    const history = turns.filter((t) => t.meta !== "error").slice(-8)
      .map((t) => ({ role: t.role === "you" ? ("user" as const) : ("assistant" as const), text: t.text }));
    setTurns((t) => [...t, { role: "you", text }]);
    setMsg("");
    ask.mutate({ text, history });
  };

  const a = detail.data?.analysis;
  return (
    <section aria-labelledby="an-h">
      <h1 id="an-h">AI analyst</h1>
      <p className="muted">
        Ask anything: what is happening on the network, how to respond to an incident, how to secure the network.
        It recommends steps and commands for you to review; it cannot approve, block or change anything itself.
        Approving a block is done by an admin on the Approvals page.
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
            a?.analysis ? (
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
                {t.role === "assistant" ? <Markdown source={t.text} /> : <p className="turn-text">{t.text}</p>}
              </li>
            ))}
            {turns.length === 0 && <li className="muted">e.g. “What is attacking 10.99.0.10 right now and what should I do?” or “How do I harden the network against SYN floods?”</li>}
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
