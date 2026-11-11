import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router";
import { api, ApiError, json, type ApprovalItem, type Approvals } from "../api/client";
import { isAdmin, useAuth } from "../auth/store";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { formatDuration, formatTime } from "../lib/format";

type Pending = { kind: "approve" | "reject" | "extend" | "permanent"; item: ApprovalItem } | null;

function ActionSummary({ a }: { a: ApprovalItem }) {
  return (
    <dl className="kv small">
      <dt>Action</dt><dd className="mono">{a.action_type} {a.attacker_ip} → {a.victim_ip}</dd>
      <dt>Reason</dt><dd>{a.reason}</dd>
      <dt>Blast radius</dt><dd className={`blast blast-${a.blast_radius}`}>{a.blast_radius} (estimated)</dd>
      <dt>Reversible</dt><dd>{a.reversible ? "yes" : "no"}{a.rollback_ttl_s ? ` · auto-rollback after ${formatDuration(a.rollback_ttl_s)}` : " · no auto-rollback (not linked to an incident)"}</dd>
      <dt>Source</dt><dd className="mono">{a.source}</dd>
      {a.incident_id && (<><dt>Incident</dt><dd><Link to={`/incidents/${encodeURIComponent(a.incident_id)}`}>{a.incident_id}</Link></dd></>)}
    </dl>
  );
}

export function ApprovalsPage() {
  const auth = useAuth();
  const admin = isAdmin(auth);
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["approvals"], queryFn: () => api<Approvals>("/api/approvals"), refetchInterval: 10_000 });
  const [pending, setPending] = useState<Pending>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const act = useMutation({
    mutationFn: async (v: { kind: NonNullable<Pending>["kind"]; id: string; reason: string }) => {
      const id = encodeURIComponent(v.id);
      if (v.kind === "approve") return api(`/actions/approve/${id}`, { method: "POST" });
      if (v.kind === "reject") return api(`/actions/reject/${id}`, { method: "POST", body: json({ reason: v.reason }) });
      if (v.kind === "extend") return api(`/api/actions/${id}/extend`, { method: "POST", body: json({ reason: v.reason, seconds: 600 }) });
      return api(`/api/actions/${id}/extend`, { method: "POST", body: json({ reason: v.reason, permanent: true }) });
    },
    onSuccess: (_d, v) => {
      setMsg({ ok: true, text: `${v.kind[0]?.toUpperCase()}${v.kind.slice(1)}: ${v.id} done.` });
      void qc.invalidateQueries({ queryKey: ["approvals"] });
      void qc.invalidateQueries({ queryKey: ["overview"] });
      void qc.invalidateQueries({ queryKey: ["incident"] });
    },
    onError: (e) => setMsg({ ok: false, text: e instanceof ApiError ? e.message : "Request failed." }),
  });

  if (q.isPending) return <p className="muted">Loading approvals…</p>;
  if (q.isError) return <p role="alert" className="error">Could not load approvals.</p>;
  const { pending: queue, active } = q.data;

  return (
    <section aria-labelledby="ap-h">
      <h1 id="ap-h">Approvals</h1>
      {!admin && <p className="banner banner-warn">You are signed in as an <strong>analyst</strong>: you can see every proposal, but only an
        admin can approve, reject or extend. Sign out and sign in with an admin key to act.</p>}
      {msg && <p role={msg.ok ? "status" : "alert"} className={msg.ok ? "ok" : "error"}>{msg.text}</p>}

      <h2>Pending ({queue.length})</h2>
      {queue.length === 0 && <p className="muted">Nothing waiting for approval.</p>}
      <div className="grid two">
        {queue.map((a) => (
          <article key={a.action_id} className="card" aria-label={`Pending action ${a.action_id}`}>
            <h3 className="mono">{a.action_id}</h3>
            <ActionSummary a={a} />
            <p className="muted small">Proposed {formatTime(a.proposed_at)}</p>
            {admin && (
              <div className="row">
                <button type="button" className="btn primary" onClick={() => setPending({ kind: "approve", item: a })}>Approve…</button>
                <button type="button" className="btn" onClick={() => setPending({ kind: "reject", item: a })}>Reject…</button>
              </div>
            )}
          </article>
        ))}
      </div>

      <h2>Active time-boxed blocks ({active.length})</h2>
      {active.length === 0 && <p className="muted">No active incident-linked blocks.</p>}
      <div className="grid two">
        {active.map((a) => (
          <article key={a.action_id} className="card" aria-label={`Active action ${a.action_id}`}>
            <h3 className="mono">{a.action_id}</h3>
            <ActionSummary a={a} />
            <p>
              {a.rollback_state === "scheduled" ? (
                <>Auto-rollback in <strong className="countdown">{formatDuration(a.seconds_until_rollback)}</strong></>
              ) : (
                <span className="warn">{a.rollback_state}</span>
              )}
            </p>
            {admin && a.rollback_state === "scheduled" && (
              <div className="row">
                <button type="button" className="btn" onClick={() => setPending({ kind: "extend", item: a })}>Extend 10 min…</button>
                <button type="button" className="btn" onClick={() => setPending({ kind: "permanent", item: a })}>Make permanent…</button>
              </div>
            )}
          </article>
        ))}
      </div>

      <ConfirmDialog
        open={pending !== null}
        title={pending ? `${pending.kind === "approve" ? "Approve and enforce" : pending.kind === "reject" ? "Reject" : pending.kind === "extend" ? "Extend block" : "Make block permanent"} ${pending.item.action_id}?` : ""}
        confirmLabel={pending?.kind === "approve" ? "Approve and enforce" : "Confirm"}
        danger={pending?.kind === "approve" || pending?.kind === "permanent"}
        reasonLabel={pending && pending.kind !== "approve" ? "Reason (recorded in the timeline)" : undefined}
        reasonRequired={pending !== null && pending.kind !== "approve"}
        onCancel={() => setPending(null)}
        onConfirm={(reason) => {
          if (pending) act.mutate({ kind: pending.kind, id: pending.item.action_id, reason });
          setPending(null);
        }}
      >
        {pending && <ActionSummary a={pending.item} />}
        {pending?.kind === "approve" && <p>This applies the mitigation now. It is logged with your identity.</p>}
      </ConfirmDialog>
    </section>
  );
}
