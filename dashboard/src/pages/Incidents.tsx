import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router";
import { api, type IncidentPage } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatDuration, formatTime, STATUSES } from "../lib/format";

const PAGE = 25;
const SORTS = [
  ["created_desc", "Newest first"],
  ["created_asc", "Oldest first"],
  ["severity_desc", "Severity high → low"],
  ["severity_asc", "Severity low → high"],
] as const;

export function IncidentsPage() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const sort = params.get("sort") ?? "created_desc";
  const minSev = params.get("min_severity") ?? "";
  const replay = params.get("replay") !== "0";
  const page = Math.max(0, Number(params.get("page") ?? "0") || 0);

  const qs = new URLSearchParams({ limit: String(PAGE), offset: String(page * PAGE), sort, include_replay: String(replay) });
  if (status) qs.set("status", status);
  if (minSev) qs.set("min_severity", minSev);

  const q = useQuery({
    queryKey: ["incidents", qs.toString()],
    queryFn: () => api<IncidentPage>(`/api/incidents?${qs.toString()}`),
    placeholderData: keepPreviousData,
    refetchInterval: 15_000,
  });

  const update = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "page") next.delete("page");
    setParams(next);
  };

  const total = q.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  return (
    <section aria-labelledby="inc-title">
      <h1 id="inc-title">Incidents</h1>
      <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Filter incidents">
        <label>
          Status
          <select value={status} onChange={(e) => update("status", e.target.value)}>
            <option value="">All</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s.replace("_", " ")}
              </option>
            ))}
          </select>
        </label>
        <label>
          Min severity
          <select value={minSev} onChange={(e) => update("min_severity", e.target.value)}>
            <option value="">Any</option>
            {[2, 3, 4, 5].map((s) => (
              <option key={s} value={s}>
                {s}+
              </option>
            ))}
          </select>
        </label>
        <label>
          Sort
          <select value={sort} onChange={(e) => update("sort", e.target.value)}>
            {SORTS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={replay} onChange={(e) => update("replay", e.target.checked ? "" : "0")} />
          Include replays
        </label>
      </form>

      {q.isError && <p role="alert" className="error">Could not load incidents.</p>}
      <div className="table-wrap">
        <table className="incidents" aria-busy={q.isFetching}>
          <caption className="sr-only">Incidents, {total} total</caption>
          <thead>
            <tr>
              <th scope="col">Severity</th>
              <th scope="col">ID</th>
              <th scope="col">Title</th>
              <th scope="col">Family</th>
              <th scope="col">Status</th>
              <th scope="col">Detected</th>
              <th scope="col">CERT-In</th>
            </tr>
          </thead>
          <tbody>
            {q.data?.items.map((i) => (
              <tr key={i.id}>
                <td><SeverityBadge severity={i.severity} /></td>
                <td className="mono"><Link to={`/incidents/${encodeURIComponent(i.id)}`}>{i.id}</Link>{i.is_replay && <span className="tag">replay</span>}</td>
                <td>{i.title}</td>
                <td>{i.attack_family.replace(/_/g, " ")}</td>
                <td><span className={`status status-${i.status}`}>{i.status.replace("_", " ")}</span></td>
                <td className="small">{formatTime(i.detected_at)}</td>
                <td className="small">
                  {i.cert_in_reported_at ? "reported" : i.cert_in_seconds_remaining === null ? "—" : formatDuration(i.cert_in_seconds_remaining)}
                </td>
              </tr>
            ))}
            {q.data && q.data.items.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">No incidents match these filters.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <nav className="pager" aria-label="Pagination">
        <button type="button" className="btn" disabled={page === 0} onClick={() => update("page", String(page - 1))}>
          Previous
        </button>
        <span aria-live="polite">
          Page {page + 1} of {pages} · {total} incidents
        </span>
        <button type="button" className="btn" disabled={page + 1 >= pages} onClick={() => update("page", String(page + 1))}>
          Next
        </button>
      </nav>
    </section>
  );
}
