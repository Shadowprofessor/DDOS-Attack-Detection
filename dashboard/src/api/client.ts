// Same-origin API client. The session cookie is HttpOnly (JS never sees it); the CSRF token
// lives only in memory and is sent on every state-changing request.

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function detailOf(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) return "Invalid input.";
  }
  return fallback;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  if (!path.startsWith("/api/")) throw new Error("api() only calls same-origin /api/ paths");
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (UNSAFE.has(method) && csrfToken) headers.set("X-CSRF-Token", csrfToken);
  const res = await fetch(path, { ...init, method, headers, credentials: "same-origin" });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!res.ok) throw new ApiError(res.status, detailOf(body, `Request failed (${res.status})`));
  return body as T;
}

export const json = (value: unknown): string => JSON.stringify(value);

// ---------------------------------------------------------------- types (mirror src/ir + overview)
export type Role = "analyst" | "admin";

export interface SessionInfo {
  role: Role;
  actor: string;
  csrf_token: string;
}

export interface IncidentSummary {
  id: string;
  title: string;
  attack_family: string;
  severity: number;
  status: string;
  csf_function: string | null;
  created_at: number;
  detected_at: number;
  contained_at: number | null;
  closed_at: number | null;
  cert_in_deadline: number | null;
  cert_in_reported_at: number | null;
  cert_in_seconds_remaining: number | null;
  is_replay: boolean;
}

export interface IncidentPage {
  total: number;
  limit: number;
  offset: number;
  sort: string;
  items: IncidentSummary[];
}

export interface Overview {
  generated_at: number;
  incidents: {
    open: number;
    by_severity_open: Record<string, number>;
    by_status: Record<string, number>;
    recent: IncidentSummary[];
    sample_size: number;
  };
  kpis: { mttc_seconds_avg: number | null; false_positive_rate: number | null };
  cert_in_timers: { incident_id: string; title: string; severity: number; seconds_remaining: number }[];
  pending_actions: number | null;
  health: { models_loaded: boolean; llm: { configured: boolean; models: string[] }; ws_clients: number };
  role: Role;
}
