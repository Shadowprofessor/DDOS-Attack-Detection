# -*- coding: utf-8 -*-
"""v5.3.0 explanations: what detected it, what it is, how sure, which ATT&CK technique, and WHY.

One shape (`schemas.Explanation`) for every layer, built by our code from the numbers the detector
actually used (never by the LLM). Example L1 reason:

    "L1: 1,416 pps to 10.99.0.10 >= 500 pps critical threshold; ICMP 99% of packets;
     20 sources -> 1 victim; T1498.001"

`confidence` is a probability only where one exists (ML, LLM self-report, rule analyst's heuristic);
threshold rules report None ("rule, not a probability").
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.agent.schemas import AnalysisResult, Explanation, IncidentAggregate


def _fmt_rules(rules: List[str]) -> List[str]:
    return [r.split(" (Benign Baseline")[0] for r in rules][:4]


def explain_l1_window(window: Dict[str, Any], l1: Dict[str, Any], crit_pps: float, warn_pps: float) -> Explanation:
    """Live L1 alert on one 1 s window, named by the L3 rules applied to that same window."""
    from src.agent.threat_analyst import rule_based_analysis
    from src.live.bridge import aggregate_from_windows

    agg = IncidentAggregate.model_validate(aggregate_from_windows([window], incident_id="live-window"))
    named = rule_based_analysis(agg)
    pps, dst = window["pps"], window["dst"]
    limit, level = (crit_pps, "critical") if pps >= crit_pps else (warn_pps, "warning")
    parts = [f"L1: {pps:,.0f} pps to {dst}" + (f" >= {limit:,.0f} pps {level} threshold" if pps >= warn_pps else "")]
    if l1.get("rules") and pps < warn_pps:  # fired on SYN or connection rate rather than pps
        parts.append(_fmt_rules(l1["rules"])[0].split(": ", 1)[-1])
    if window.get("hint"):
        parts.append(f"{window['hint']} of packets")
    parts.append(f"{window.get('unique_src', 0)} source{'s' if window.get('unique_src') != 1 else ''} -> 1 victim")
    if named.mitre_ids:
        parts.append(", ".join(named.mitre_ids))
    return Explanation(
        detected_by="L1 (live 1 s window, rate threshold)",
        attack_type=named.attack_type if not named.attack_type.startswith("Benign") else (l1.get("vector") or "Rate anomaly"),
        confidence=None, mitre=named.mitre_ids, reason="; ".join(parts),
        evidence=_fmt_rules(l1.get("rules") or []) + ([named.reason] if named.reason else []))


def explain_analysis(result: AnalysisResult, agg: Optional[IncidentAggregate] = None) -> Explanation:
    a = result.analysis
    by = "L3 rule analyst" if result.source == "rules" else f"L3 LLM analyst ({result.source.removeprefix('llm:')})"
    reason = a.reason or (a.evidence[0] if a.evidence else a.report_summary)
    if result.source != "rules" and not reason.startswith("L3"):
        reason = f"L3 ({result.source.removeprefix('llm:')}): {reason}"
    ev = list(a.evidence)
    if result.source != "rules" and agg is not None:  # show what the deterministic rules say next to the LLM
        from src.agent.threat_analyst import rule_based_analysis

        rules = rule_based_analysis(agg)
        ev.append(f"Rule analyst on the same data: {rules.attack_type}" + (f" ({rules.reason})" if rules.reason else ""))
    return Explanation(detected_by=by, attack_type=a.attack_type, confidence=a.confidence, mitre=a.mitre_ids,
                       reason=reason[:800], evidence=ev[:12])


def explain_score(is_attack: bool, label: str, confidence: Optional[float], basis: str,
                  h6: Optional[Dict[str, Any]] = None, h9: Optional[Dict[str, Any]] = None,
                  dst: Optional[str] = None) -> Optional[Explanation]:
    """/score/flow verdict. basis: 'ml' (the ensemble decided) or 'multi_layer' (rate corroboration)."""
    if not is_attack:
        return None
    if basis == "multi_layer":
        ev = _fmt_rules((h6 or {}).get("triggered_rules") or []) + list((h9 or {}).get("anomaly_reasons") or [])
        reason = "Rate corroboration (the ML said Benign): " + ("; ".join(ev) if ev else "victim rate over threshold")
        return Explanation(detected_by="L1 rate corroboration (H6/H9)", attack_type=label, confidence=None,
                           mitre=["T1498"], reason=reason[:800], evidence=ev[:12])
    return Explanation(detected_by="L2 ML ensemble", attack_type=label, confidence=confidence, mitre=[],
                       reason=(f"L2: the flow's 77 CICFlowMeter features match class {label}"
                               + (f" (confidence {confidence:.2f})" if confidence is not None else "")
                               + (f"; flow to {dst}" if dst else "")),
                       evidence=[])
