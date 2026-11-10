// Severity -> visual token. Red is reserved for severity 5 (critical) only.
export type SeverityTone = "critical" | "high" | "medium" | "low" | "info";

export function severityTone(sev: number): SeverityTone {
  if (sev >= 5) return "critical";
  if (sev === 4) return "high";
  if (sev === 3) return "medium";
  if (sev === 2) return "low";
  return "info";
}

export const SEVERITY_LABEL: Record<SeverityTone, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  const neg = seconds < 0;
  let s = Math.floor(Math.abs(seconds));
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  const body = h > 0 ? `${h}h ${String(m).padStart(2, "0")}m` : `${m}m ${String(s).padStart(2, "0")}s`;
  return neg ? `overdue ${body}` : body;
}

export function formatTime(epoch: number | null | undefined): string {
  if (!epoch) return "—";
  return new Date(epoch * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function formatPercent(v: number | null | undefined): string {
  return v === null || v === undefined ? "—" : `${(v * 100).toFixed(1)}%`;
}

export const STATUSES = [
  "new", "triage", "investigating", "contained", "eradicated", "recovered", "closed", "false_positive",
] as const;
