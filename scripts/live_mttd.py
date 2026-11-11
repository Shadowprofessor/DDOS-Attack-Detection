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
    from lab.library import load_scenarios
    from lab.safety import load_scope

    run = Path(sys.argv[1])
    manifest = json.loads((run / "manifest.json").read_text())
    log = [json.loads(x) for x in (run / "live_bridge.jsonl").read_text().splitlines() if x.strip()]
    scs = load_scenarios()
    victim = str(load_scope().hosts["victim"])
    offline = {}
    if OFFLINE.is_file():
        offline = {m["scenario"]: m for m in json.loads(OFFLINE.read_text()).get("mttd", [])}
    r = analyse(manifest, log, victim, {k: v.attack for k, v in scs.items()}, offline)
    r["run"] = run.name
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(r, indent=2), encoding="utf-8")
    md = render(r, run.name)
    doc = DOC.read_text(encoding="utf-8")
    if MARK_A in doc:
        doc = doc[:doc.index(MARK_A) + len(MARK_A)] + "\n" + md + "\n" + doc[doc.index(MARK_B):]
        with DOC.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(doc)
    print(md)


if __name__ == "__main__":
    main()
