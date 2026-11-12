# -*- coding: utf-8 -*-
"""Real-time MTTD from a live demo run (v5.2.0).

    python scripts/live_mttd.py data/lab_runs/live1

Joins the orchestrator's manifest (when each scenario *started*, WSL2 clock) with the bridge log
(when the platform raised each alert, Windows clock) and reports, per scenario:

* **window_s**: end of the first alerting 1 s window - scenario start. Both on the WSL2 clock: how
  much traffic the detector needed.
* **website_s**: server time the L1 alert was published (to /ws/live) - scenario start. The
  number the brief asks for: "attack start -> first alert on the website". It crosses clocks, see
  `clock` in the output.
* **incident_s**: the incident created through the IR API - scenario start.
* **l2_s**: first "attack" verdict that came from the ML ensemble (L2) for a flow to the victim.
* **corroboration_s**: first "attack" verdict that came from /score/flow's multi-layer rate
  corroboration instead (the ML said otherwise). Kept apart so it is never reported as ML.
  Flows are sampled, so both are upper bounds; on benign scenarios they are false positives.
Layers that never fired are reported as "not detected". Benign scenarios that alerted are
false positives. Nothing is estimated.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
OUT_JSON = REPO / "docs" / "eval" / "live" / "results.json"
DOC = REPO / "docs" / "DETECTION_LATENCY.md"
OFFLINE = REPO / "docs" / "eval" / "latency" / "results.json"
MARK_A, MARK_B = "<!-- LIVE:START -->", "<!-- LIVE:END -->"


def _r(x: Optional[float]) -> Optional[float]:
    return None if x is None else round(x, 2)


def analyse(manifest: dict, log: List[dict], victim: str, attacks: Dict[str, bool],
            offline: Optional[Dict[str, dict]] = None, tail_s: float = 5.0) -> dict:
    alerts = [e for e in log if e.get("event") == "alert" and (e.get("episode") or {}).get("dst") == victim]
    incidents = {e["episode_id"]: e for e in log if e.get("event") == "incident_created" and e.get("status") == 201}
    analysed = {e["incident_id"]: e for e in log if e.get("event") == "incident_analyzed"}
    flows = [e for e in log if e.get("event") == "flow_scored" and e.get("dst") == victim]
    posts = [e for e in log if e.get("event") == "windows_posted" and e.get("status") == 200]
    rows = []
    for run in manifest.get("runs", []):
        sid, t0, t1 = run["scenario"], run["started_at"], run["ended_at"] + tail_s
        mine = [a for a in alerts if t0 - 1.0 <= a["episode"]["window_start"] <= t1]
        first = min(mine, key=lambda a: a["episode"]["window_start"]) if mine else None
        ep = (first or {}).get("episode") or {}
        inc = incidents.get(ep.get("id")) if first else None
        ana = analysed.get((inc or {}).get("incident_id")) if inc else None
        hits = [f for f in flows if f.get("is_attack") and t0 <= (f.get("flow_end") or 0) <= t1]
        l2 = [f for f in hits if f.get("basis") == "ml"]
        corr = [f for f in hits if f.get("basis") == "multi_layer"]
        off = (offline or {}).get(sid) or {}
        rows.append({
            "scenario": sid, "attack": attacks.get(sid), "duration_s": _r(run["ended_at"] - t0),
            "alerted": bool(first),
            "window_s": _r(ep["window_start"] + 1.0 - t0) if first else None,
            "website_s": _r(ep["opened_at"] - t0) if first else None,
            "incident_s": _r(inc["ack_at"] - t0) if inc else None,
            "l3_verdict": (ana or {}).get("attack_type"),
            "l3_source": (ana or {}).get("source"),
            "l2_s": _r(min(f["ack_at"] for f in l2) - t0) if l2 else None,
            "l2_label": l2[0]["label"] if l2 else None,
            "corroboration_s": _r(min(f["ack_at"] for f in corr) - t0) if corr else None,
            "scored_flows": sum(1 for f in flows if t0 <= (f.get("flow_end") or 0) <= t1),
            "attack_verdicts": len(hits),
            "episodes": len(mine),
            "offline_l1_s": off.get("L1_first_alert_s"),
            "offline_run": off.get("run"),
        })
    lags = sorted(p["ack_at"] - p["last_window_end"] for p in posts if p.get("last_window_end"))
    skews = [p["skew_s"] for p in posts if p.get("skew_s") is not None]
    return {"victim": victim, "results": rows,
            "clock": {"min_wall_minus_packet_s": _r(min(skews)) if skews else None,
                      "post_lag_p50_s": _r(lags[len(lags) // 2]) if lags else None,
                      "post_lag_max_s": _r(lags[-1]) if lags else None,
                      "note": "wall = Windows clock at the bridge; packet = WSL2 capture clock. The minimum gap is "
                              "an upper bound on (WSL2 clock behind Windows + capture-to-read delay)."}}


def _cell(v, unit="") -> str:
    return "not detected" if v is None else f"{v}{unit}"


BELOW_PPS = 100.0  # L1 warning threshold: "traffic below threshold"
HOLD_WINDOWS = 3   # ...for this many consecutive 1 s windows


def containment(manifest: dict, log: List[dict], victim: str) -> List[dict]:
    """v5.4.0 MTTC per applied lab rule: approval -> applied -> victim traffic below BELOW_PPS for
    HOLD_WINDOWS consecutive windows. Approval is on the platform (Windows) clock; windows and the
    enforcer on the WSL2 clock (the measured skew is reported with the run)."""
    queued = {e["action_id"]: e for e in log if e.get("event") == "enforcement_queued" and e.get("op") == "apply"}
    applied = [e for e in log if e.get("event") == "enforcement_reported" and e.get("state") == "applied"]
    wins = [e for e in log if e.get("event") == "victim_window" and e.get("dst") == victim]  # v5.4.0 first format
    wins += [{"dst": d, "end": end, "pps": pps} for e in log if e.get("event") == "victim_windows"
             for d, end, pps in e.get("windows", []) if d == victim]  # batched format
    wins.sort(key=lambda e: e["end"])
    out = []
    for a in applied:
        q = queued.get(a["action_id"]) or {}
        approved, t_apply = q.get("approved_at"), a.get("ts")
        if t_apply is None:
            continue
        run = next((r for r in manifest.get("runs", []) if r["started_at"] <= t_apply <= r["ended_at"] + 5), None)
        after = [w for w in wins if w["end"] > t_apply]
        below = None
        for i in range(len(after)):
            seg = after[i:i + HOLD_WINDOWS]
            if len(seg) == HOLD_WINDOWS and all(w["pps"] < BELOW_PPS for w in seg):
                below = seg[0]
                break
        out.append({
            "action_id": a["action_id"], "target": q.get("target"), "scenario": run["scenario"] if run else None,
            "approval_to_applied_s": round(t_apply - approved, 2) if approved else None,
            "mttc_s": round(below["end"] - approved, 2) if below and approved else None,
            "applied_to_below_s": round(below["end"] - t_apply, 2) if below else None,
            "attack_start_to_contained_s": round(below["end"] - run["started_at"], 2) if below and run else None,
            "pps_before": max((w["pps"] for w in wins if t_apply - 5 <= w["end"] <= t_apply), default=None),
            "pps_after": below["pps"] if below else None,
        })
    return out


def victim_port_rates(ovs_rows: List[dict], victim_role: str = "victim") -> List[tuple]:
    """(ts, packets/s sent by the switch INTO the victim's port) from consecutive OVS samples."""
    out, prev = [], None
    for r in ovs_rows:
        port = next((p for p in r.get("ports", []) if p.get("host") == victim_role), None)
        if port is None:
            continue
        if prev is not None and r["ts"] > prev[0] and port["tx_packets"] >= prev[1]:
            out.append((r["ts"], (port["tx_packets"] - prev[1]) / (r["ts"] - prev[0])))
        prev = (r["ts"], port["tx_packets"])
    return out


def containment_ovs(manifest: dict, log: List[dict], ovs_rows: List[dict], hold: int = 2) -> List[dict]:
    """v5.4.0 MTTC from the SWITCH (ground truth): approval -> the victim port's packet rate stays below
    BELOW_PPS for `hold` consecutive OVS samples (~2 s apart). live5 showed pcap timestamps arriving in
    bursts under load, so 1 s pcap windows are not trusted for this."""
    queued = {e["action_id"]: e for e in log if e.get("event") == "enforcement_queued" and e.get("op") == "apply"}
    applied = [e for e in log if e.get("event") == "enforcement_reported" and e.get("state") == "applied"]
    rates = victim_port_rates(ovs_rows)
    out = []
    for a in applied:
        q = queued.get(a["action_id"]) or {}
        approved, t_apply = q.get("approved_at"), a.get("ts")
        if t_apply is None:
            continue
        run = next((r for r in manifest.get("runs", []) if r["started_at"] <= t_apply <= r["ended_at"] + 5), None)
        before = [pps for ts, pps in rates if t_apply - 8 <= ts <= t_apply]
        end = (run["ended_at"] if run else float("inf"))
        # only while the attack is still running: traffic stopping because the scenario ENDED is not containment
        after = [(ts, pps) for ts, pps in rates if t_apply + 0.5 < ts <= end]
        below = None
        for i in range(len(after)):
            seg = after[i:i + hold]
            if len(seg) == hold and all(pps < BELOW_PPS for _, pps in seg):
                below = seg[0]
                break
        window_after = [pps for ts, pps in after if ts <= t_apply + 15]
        out.append({
            "action_id": a["action_id"], "target": q.get("target"), "scenario": run["scenario"] if run else None,
            "approval_to_applied_s": round(t_apply - approved, 2) if approved else None,
            "mttc_s": round(below[0] - approved, 2) if below and approved else None,
            "attack_start_to_contained_s": round(below[0] - run["started_at"], 2) if below and run else None,
            "victim_pps_before": round(sum(before) / len(before)) if before else None,
            "victim_pps_after_15s": round(sum(window_after) / len(window_after)) if window_after else None,
            "reduction": (round(1 - (sum(window_after) / len(window_after)) / (sum(before) / len(before)), 3)
                          if before and window_after and sum(before) else None),
            "source": "OVS port counters",
        })
    return out


def render_containment(rows: List[dict]) -> str:
    if not rows:
        return "No lab containment was applied in this run."
    if rows[0].get("source") == "OVS port counters":
        cell = lambda v: "not reached" if v is None else f"{v}"  # noqa: E731
        lines = ["| Scenario | Rule target | Approval -> applied (s) | **MTTC: approval -> victim < 100 pps (s)** | "
                 "Attack start -> contained (s) | Victim pps before -> 15 s after | Reduction |",
                 "|---|---|---:|---:|---:|---|---:|"]
        for r in rows:
            red = "—" if r["reduction"] is None else f"{r['reduction']:.0%}"
            lines.append(f"| `{r['scenario']}` | {r['target']} | {cell(r['approval_to_applied_s'])} | {cell(r['mttc_s'])} | "
                         f"{cell(r['attack_start_to_contained_s'])} | {cell(r['victim_pps_before'])} -> "
                         f"{cell(r['victim_pps_after_15s'])} | {red} |")
        return "\n".join(lines)
    cell = lambda v: "not reached" if v is None else f"{v}"  # noqa: E731
    lines = ["| Scenario | Rule target | Approval -> applied (s) | **MTTC: approval -> below 100 pps (s)** | "
             "Attack start -> contained (s) | pps before -> after |", "|---|---|---:|---:|---:|---|"]
    for r in rows:
        lines.append(f"| `{r['scenario']}` | {r['target']} | {cell(r['approval_to_applied_s'])} | {cell(r['mttc_s'])} | "
                     f"{cell(r['attack_start_to_contained_s'])} | {cell(r['pps_before'])} -> {cell(r['pps_after'])} |")
    return "\n".join(lines)


def render(r: dict, run_name: str) -> str:
    c = r["clock"]
    lines = [f"Live run `{run_name}`, victim `{r['victim']}`. Seconds from scenario start (WSL2 clock).",
             "",
             "| Scenario | Attack? | First alerting window | **Alert on website** | Incident opened | L3 verdict | L2 (ML) attack verdict* | Rate-corroboration verdict* | Offline L1 MTTD |",
             "|---|---|---:|---:|---:|---|---:|---:|---:|"]
    for x in r["results"]:
        benign = x["attack"] is False
        if benign:
            alert = "**false positive** " + _cell(x["website_s"]) if x["alerted"] else "no alert (correct)"
        else:
            alert = _cell(x["website_s"])

        def verdict(v):
            if v is None:
                return "none (correct)" if benign else "not detected"
            return ("**false positive** " if benign else "") + str(v)

        lines.append(f"| `{x['scenario']}` | {'yes' if x['attack'] else 'no'} | {_cell(x['window_s'])} | {alert} | "
                     f"{_cell(x['incident_s'])} | {x['l3_verdict'] or '—'} | {verdict(x['l2_s'])} | "
                     f"{verdict(x['corroboration_s'])} | {_cell(x['offline_l1_s'])} |")
    lines += ["", f"\\* /score/flow is called on sampled flows (`--flows-per-s`), so these are upper bounds. Clock: smallest "
              f"(Windows wall - WSL2 packet time) gap {c['min_wall_minus_packet_s']} s; window post lag p50 "
              f"{c['post_lag_p50_s']} s, max {c['post_lag_max_s']} s."]
    return "\n".join(lines)


def main() -> None:  # pragma: no cover - CLI
    from lab.library import CATALOGS, load_scenarios
    from lab.safety import load_scope

    run = Path(sys.argv[1])
    manifest = json.loads((run / "manifest.json").read_text())
    log = [json.loads(x) for x in (run / "live_bridge.jsonl").read_text().splitlines() if x.strip()]
    scs = {}
    for cat in CATALOGS.values():  # main, train and demo scenarios
        scs.update(load_scenarios(cat))
    victim = str(load_scope().hosts["victim"])
    offline = {}
    if OFFLINE.is_file():
        offline = {m["scenario"]: m for m in json.loads(OFFLINE.read_text()).get("mttd", [])}
    r = analyse(manifest, log, victim, {k: v.attack for k, v in scs.items()}, offline)
    r["run"] = run.name
    ovs_path = run / "ovs_ports.jsonl"
    ovs_rows = [json.loads(x) for x in ovs_path.read_text().splitlines() if x.strip()] if ovs_path.is_file() else []
    r["containment"] = containment_ovs(manifest, log, ovs_rows) if ovs_rows else containment(manifest, log, victim)
    out = OUT_JSON.parent / f"{run.name}.json"  # one file per run; docs are written by hand from these
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(r, indent=2), encoding="utf-8")
    md = render(r, run.name) + "\n\n**Containment (v5.4.0)**\n\n" + render_containment(r["containment"])
    print(md)
    print("wrote", out)


if __name__ == "__main__":
    main()
