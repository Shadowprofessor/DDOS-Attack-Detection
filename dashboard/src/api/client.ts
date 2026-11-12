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
  // Same-origin API only: /api/* plus the approval-gate endpoints /actions/*.
  if (!(path.startsWith("/api/") || path.startsWith("/actions/"))) throw new Error("api() only calls same-origin API paths");
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

export interface TimelineEvent {
  seq: number;
  ts: number;
  actor: string;
  kind: string;
  detail: Record<string, unknown>;
  hash: string;
}

export interface ActionLink {
  action_id: string;
  rollback_state: string;
  ttl_s: number | null;
  approved_at: number | null;
  rollback_at: number | null;
  rolled_back_at: number | null;
  permanent_reason: string | null;
  attempts: number;
  last_error: string | null;
}

export interface RecommendedAction {
  action: string;
  blast_radius: "low" | "medium" | "high";
  reversible: boolean;
  requires_human: boolean;
}

export interface Explanation {
  detected_by: string;
  attack_type: string;
  confidence: number | null;
  mitre: string[];
  reason: string;
  evidence?: string[];
}

export interface PlanStep {
  rank: number;
  action: "LAB_OVS_DROP" | "LAB_OVS_PORT_DROP" | "RATE_LIMIT_ADVICE" | "MONITOR" | "ESCALATE_UPSTREAM";
  target: string;
  blast_radius: "low" | "medium" | "high";
  reversible: boolean;
  ttl_s: number;
  rationale: string;
}

export interface AgentPlan {
  attack_type: string;
  evidence: string[];
  reason: string;
  confidence: number;
  false_positive_assessment: string;
  mitre_ids: string[];
  plan: PlanStep[];
  source: string;
  degraded_reason?: string;
  policy_violations: string[];
  tool_trace: { tool: string; ok?: boolean }[];
  latency_ms?: number;
}

export interface AnalysisResult {
  explanation?: Explanation | null;
  agent?: AgentPlan | null;
  /** absent when only an agent plan has been stored (v5.4.0) */
  analysis?: {
    attack_type: string;
    mitre_ids: string[];
    severity: number;
    confidence: number;
    evidence: string[];
    false_positive_assessment: string;
    recommended_actions: RecommendedAction[];
    next_queries: string[];
    report_summary: string;
  };
  source: string;
  prompt_version?: string;
  degraded?: boolean;
  degraded_reason?: string | null;
  policy_violations?: string[];
  suspicious_telemetry?: number;
  cached?: boolean;
}

export interface IncidentDetail extends IncidentSummary {
  aggregate: Record<string, unknown> | null;
  analysis: AnalysisResult | null;
  containment_justification: string | null;
  events: TimelineEvent[];
  actions: ActionLink[];
  playbook_runs: { playbook_id: string; step: string; status: string; actor: string; ts: number }[];
  chain: { ok: boolean; events: number; broken_at: number | null };
  allowed_transitions: string[];
  suggested_playbooks: string[];
}

export interface PlaybookStep {
  id: string;
  title: string;
  kind: "check" | "propose_action" | "notify" | "document";
  requires_role: Role;
  description: string;
}

export interface Playbook {
  id: string;
  name: string;
  attack_families: string[];
  mitre: string[];
  steps: PlaybookStep[];
}

export interface ApprovalItem {
  action_id: string;
  action_type: string;
  attacker_ip: string;
  victim_ip: string;
  reason: string;
  confidence: number | null;
  source: string;
  status: string;
  proposed_at: number;
  approved_at: number | null;
  approver: string | null;
  incident_id: string | null;
  blast_radius: "low" | "medium" | "high";
  reversible: boolean;
  rollback_ttl_s: number | null;
  rollback_state?: string;
  rollback_at?: number | null;
  seconds_until_rollback?: number | null;
  proposed_commands: string[];
}

export interface Approvals {
  pending: ApprovalItem[];
  active: ApprovalItem[];
  default_ttl_s: number;
}

/** Admin-only by role; the server enforces it regardless of what the UI shows. */
export const ANALYST_TRANSITIONS = new Set(["triage", "investigating"]);
