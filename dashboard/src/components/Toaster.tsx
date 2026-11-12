import { Link } from "react-router";
import { dismiss, useToasts } from "../alerts/alerts";

/** On-screen SOC alerts (v6.0.0). Critical and high alerts are announced assertively. */
export function Toaster() {
  const toasts = useToasts();
  return (
    <section className="toaster" aria-label="Alerts">
      {toasts.map((a) => (
        <div key={a.id} className={`toast toast-${a.level}`} role={a.level === "critical" || a.level === "high" ? "alert" : "status"}>
          <div className="toast-head">
            <span className={`sev sev-${a.level === "info" ? "low" : a.level}`}>{a.level}</span>
            <strong className="toast-title">{a.title}</strong>
            <button type="button" className="btn ghost toast-x" aria-label={`Dismiss alert: ${a.title}`} onClick={() => dismiss(a.id)}>
              ×
            </button>
          </div>
          {a.reason && <p className="toast-reason">{a.reason}</p>}
          <div className="toast-foot small muted">
            {a.incident_id && (
              <Link to={`/incidents/${a.incident_id}`} onClick={() => dismiss(a.id)}>
                Open {a.incident_id}
              </Link>
            )}
            {a.suppressed > 0 && <span> · +{a.suppressed} similar alerts held back</span>}
          </div>
        </div>
      ))}
    </section>
  );
}
