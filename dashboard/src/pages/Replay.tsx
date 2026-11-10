import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router";
import { api, ApiError, json } from "../api/client";

interface ReplayResult {
  incident: { id: string; title: string; attack_family: string; severity: number };
  stages: { layer: string; [k: string]: unknown }[];
  speed: number;
}

export function ReplayPage() {
  const qc = useQueryClient();
  const scen = useQuery({ queryKey: ["scenarios"], queryFn: () => api<{ scenarios: string[] }>("/api/replay/scenarios") });
  const [scenario, setScenario] = useState("");
  const [speed, setSpeed] = useState(60);
  const run = useMutation({
    mutationFn: (name: string) => api<ReplayResult>("/api/replay", { method: "POST", body: json({ scenario: name, speed }) }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["incidents"] });
      void qc.invalidateQueries({ queryKey: ["overview"] });
    },
  });
  const list = scen.data?.scenarios ?? [];
  const chosen = scenario || list[0] || "";

  return (
    <section aria-labelledby="rp-h">
      <h1 id="rp-h">Replay</h1>
      <p className="muted">
        Replays a stored incident through L1 alerts → L2 verdict → rule-based L3 into a <strong>replay incident</strong>.
        No live traffic, no LLM call, and any action a playbook proposes goes to an isolated dry-run queue.
      </p>
      <form className="filters" onSubmit={(e) => { e.preventDefault(); if (chosen) run.mutate(chosen); }}>
        <label>
          Scenario
          <select value={chosen} onChange={(e) => setScenario(e.target.value)}>
            {list.map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
          </select>
        </label>
        <label>
          Speed (× real time)
          <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
            {[1, 10, 60, 600, 10000].map((s) => <option key={s} value={s}>{s}×</option>)}
          </select>
        </label>
        <button type="submit" className="btn primary" disabled={!chosen || run.isPending}>
          {run.isPending ? "Replaying…" : "Run replay"}
        </button>
      </form>
      {run.isError && <p role="alert" className="error">{run.error instanceof ApiError ? run.error.message : "Replay failed."}</p>}
      {run.data && (
        <div className="card" aria-live="polite">
          <h2>Result</h2>
          <p>
            Created <Link to={`/incidents/${encodeURIComponent(run.data.incident.id)}`}>{run.data.incident.id}</Link>:{" "}
            {run.data.incident.title} (family {run.data.incident.attack_family.replace(/_/g, " ")}, severity {run.data.incident.severity})
          </p>
          <ol className="timeline">
            {run.data.stages.map((s, i) => (
              <li key={i}>
                <strong>{s.layer}</strong>
                <span className="small">{Object.entries(s).filter(([k]) => k !== "layer").map(([k, v]) => `${k}: ${String(v)}`).join(" · ")}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}
