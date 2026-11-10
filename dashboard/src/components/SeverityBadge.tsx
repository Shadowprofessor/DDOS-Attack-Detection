import { SEVERITY_LABEL, severityTone } from "../lib/format";

export function SeverityBadge({ severity }: { severity: number }) {
  const tone = severityTone(severity);
  return (
    <span className={`sev sev-${tone}`} title={`Severity ${severity}/5`}>
      {severity} · {SEVERITY_LABEL[tone]}
    </span>
  );
}
