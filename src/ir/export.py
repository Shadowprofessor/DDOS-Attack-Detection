# -*- coding: utf-8 -*-
"""
Incident report export: Markdown and PDF (reportlab).

Every incident-derived string is untrusted (it can come from telemetry or the LLM), so it is
escaped for the target format: Markdown/HTML metacharacters are backslash- or entity-escaped and
newlines collapsed (no injected headings, links or raw HTML); PDF text goes through
`xml.sax.saxutils.escape` because reportlab Paragraphs parse a mini-markup.
"""
from __future__ import annotations

import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

AI_LABEL = "AI-generated recommendation - review before acting"
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|~>-])")


def md_escape(value: Any, max_len: int = 2000) -> str:
    s = "" if value is None else str(value)
    s = s[:max_len]
    s = re.sub(r"[\r\n\t]+", " ", s)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", s)


def _iso(ts: Optional[float]) -> str:
    return "-" if ts is None else datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _detail_text(detail: Any) -> str:
    if isinstance(detail, dict):
        return ", ".join(f"{k}={v if not isinstance(v, (dict, list)) else json.dumps(v, default=str)}"
                         for k, v in detail.items())
    return str(detail)


def _sections(inc: Dict[str, Any]) -> Dict[str, Any]:
    analysis = ((inc.get("analysis") or {}).get("analysis")) or None
    provenance = inc.get("analysis") or {}
    # v5.3.0 "why it was flagged": live L1 alert reasons (aggregate.alert_history) + the analyst's explanation
    why = [{"detected_by": f"{h.get('layer', '?')} alert", "attack_type": h.get("rule"), "confidence": None,
            "mitre": [], "reason": h.get("detail")} for h in ((inc.get("aggregate") or {}).get("alert_history") or [])]
    if provenance.get("explanation"):
        why.append(provenance["explanation"])
    return {"analysis": analysis, "provenance": provenance, "why": why}


def _why_line(x: Dict[str, Any]) -> str:
    conf = x.get("confidence")
    return (f"{x.get('detected_by')}: {x.get('attack_type') or '-'}"
            f" (confidence {'n/a, rule' if conf is None else f'{conf:.2f}'}"
            f"{'; ' + ', '.join(x['mitre']) if x.get('mitre') else ''}). Reason: {x.get('reason') or '-'}")


def to_markdown(inc: Dict[str, Any]) -> str:
    e = md_escape
    sec = _sections(inc)
    chain = inc.get("chain") or {}
    out: List[str] = [
        f"# Incident report {e(inc['id'])}",
        "",
        f"**Title:** {e(inc['title'])}  ",
        f"**Status:** {e(inc['status'])} (CSF 2.0: {e(inc.get('csf_function'))})  ",
        f"**Attack family:** {e(inc['attack_family'])}  ",
        f"**Severity:** {int(inc['severity'])}/5  ",
        f"**Detected:** {_iso(inc.get('detected_at'))}  ",
        f"**Contained:** {_iso(inc.get('contained_at'))}  ",
        f"**Closed:** {_iso(inc.get('closed_at'))}  ",
    ]
    if inc.get("is_replay"):
        out.append("**REPLAY INCIDENT** (synthetic; no real actions)  ")
    if inc.get("cert_in_deadline"):
        out.append(f"**CERT-In deadline:** {_iso(inc['cert_in_deadline'])} "
                   f"(reported: {_iso(inc.get('cert_in_reported_at'))})  ")
    if sec["why"]:
        out += ["", "## Why it was flagged", ""] + [f"- {e(_why_line(x))}" for x in sec["why"]]
    out += ["", "## Summary", ""]
    a = sec["analysis"]
    if a:
        out += [f"> {AI_LABEL} (source: {e(sec['provenance'].get('source'))})", "",
                f"**Assessed attack:** {e(a.get('attack_type'))}  ",
                f"**MITRE ATT&CK:** {e(', '.join(a.get('mitre_ids') or []))}  ",
                f"**Confidence:** {e(a.get('confidence'))}  ", "",
                e(a.get("report_summary")), "", "**Evidence:**", ""]
        out += [f"- {e(x)}" for x in a.get("evidence") or []]
        out += ["", "**Recommended actions (not executed):**", ""]
        out += [f"- {e(r.get('action'))} (blast radius {e(r.get('blast_radius'))}, "
                f"reversible={e(r.get('reversible'))})" for r in a.get("recommended_actions") or []]
        out += ["", f"**False-positive assessment:** {e(a.get('false_positive_assessment'))}"]
    else:
        out.append("No analyst output attached.")
    out += ["", "## Actions and approvals", ""]
    acts = inc.get("actions") or []
    if acts:
        out += ["| Action | Rollback state | Approved | Rollback at | Rolled back |", "|---|---|---|---|---|"]
        for x in acts:
            out.append(f"| {e(x['action_id'])} | {e(x['rollback_state'])} | {_iso(x.get('approved_at'))} | "
                       f"{_iso(x.get('rollback_at'))} | {_iso(x.get('rolled_back_at'))} |")
    else:
        out.append("No mitigation actions linked.")
    out += ["", "## Timeline", "", "| # | Time | Actor | Event | Detail |", "|---|---|---|---|---|"]
    for ev in inc.get("events") or []:
        out.append(f"| {ev['seq']} | {_iso(ev['ts'])} | {e(ev['actor'])} | {e(ev['kind'])} | "
                   f"{e(_detail_text(ev['detail']), 500)} |")
    status = "VERIFIED" if chain.get("ok") else f"BROKEN at event {chain.get('broken_at')}"
    out += ["", "## Timeline integrity", "",
            f"Hash chain over {chain.get('events', 0)} events: **{status}**", ""]
    return "\n".join(out)


def to_pdf(inc: Dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    def p(text: Any, style: str = "BodyText") -> Paragraph:
        return Paragraph(xml_escape("" if text is None else str(text)[:3000]), styles[style])

    styles = getSampleStyleSheet()
    sec = _sections(inc)
    chain = inc.get("chain") or {}
    story: List[Any] = [p(f"Incident report {inc['id']}", "Title"), p(inc["title"], "Heading2")]
    meta = [("Status", f"{inc['status']} (CSF 2.0: {inc.get('csf_function')})"),
            ("Attack family", inc["attack_family"]), ("Severity", f"{int(inc['severity'])}/5"),
            ("Detected", _iso(inc.get("detected_at"))), ("Contained", _iso(inc.get("contained_at"))),
            ("Closed", _iso(inc.get("closed_at")))]
    if inc.get("is_replay"):
        meta.append(("Replay", "synthetic incident; no real actions"))
    if inc.get("cert_in_deadline"):
        meta.append(("CERT-In deadline", _iso(inc["cert_in_deadline"])))
    story.append(Table([[p(k), p(v)] for k, v in meta], colWidths=[40 * mm, 130 * mm]))
    if sec["why"]:
        story += [Spacer(1, 6 * mm), p("Why it was flagged", "Heading2")] + [p(f"- {_why_line(x)}") for x in sec["why"]]
    story += [Spacer(1, 6 * mm), p("Summary", "Heading2")]
    a = sec["analysis"]
    if a:
        story += [p(f"{AI_LABEL} (source: {sec['provenance'].get('source')})", "Italic"),
                  p(f"Assessed attack: {a.get('attack_type')} | MITRE: {', '.join(a.get('mitre_ids') or [])}"),
                  p(a.get("report_summary"))]
        story += [p(f"- {x}") for x in a.get("evidence") or []]
        story.append(p("Recommended actions (not executed):", "Heading3"))
        story += [p(f"- {r.get('action')} (blast radius {r.get('blast_radius')})")
                  for r in a.get("recommended_actions") or []]
    else:
        story.append(p("No analyst output attached."))
    story += [Spacer(1, 4 * mm), p("Actions and approvals", "Heading2")]
    acts = inc.get("actions") or []
    if acts:
        rows = [[p("Action"), p("State"), p("Approved"), p("Rolled back")]]
        rows += [[p(x["action_id"]), p(x["rollback_state"]), p(_iso(x.get("approved_at"))),
                  p(_iso(x.get("rolled_back_at")))] for x in acts]
        story.append(Table(rows, repeatRows=1))
    else:
        story.append(p("No mitigation actions linked."))
    story += [Spacer(1, 4 * mm), p("Timeline", "Heading2")]
    rows = [[p("#"), p("Time"), p("Actor"), p("Event"), p("Detail")]]
    rows += [[p(ev["seq"]), p(_iso(ev["ts"])), p(ev["actor"]), p(ev["kind"]), p(_detail_text(ev["detail"])[:500])]
             for ev in inc.get("events") or []]
    t = Table(rows, colWidths=[8 * mm, 38 * mm, 32 * mm, 28 * mm, 64 * mm], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
    status = "VERIFIED" if chain.get("ok") else f"BROKEN at event {chain.get('broken_at')}"
    story += [Spacer(1, 4 * mm), p("Timeline integrity", "Heading2"),
              p(f"Hash chain over {chain.get('events', 0)} events: {status}")]

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, title=f"Incident {inc['id']}",
                      leftMargin=15 * mm, rightMargin=15 * mm).build(story)
    return buf.getvalue()
