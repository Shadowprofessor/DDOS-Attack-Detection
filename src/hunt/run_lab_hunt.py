# -*- coding: utf-8 -*-
"""Execute the hunts over a recorded lab run's flows (python -m src.hunt.run_lab_hunt data/lab_runs/run2)."""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

from src.hunt.rules import RULES, FlowRecord

REPO = Path(__file__).resolve().parent.parent.parent
OUT = REPO / "docs" / "hunts" / "results.json"


def lab_flow_records(run_dir: Path, scenario: str):  # pragma: no cover - needs pcaps
    from src.eval.lab_analysis import flows_from_pcap

    recs = []
    for f in flows_from_pcap(run_dir / f"{scenario}.pcap"):
        ft = f["features"]
        win = ft.get("Init Fwd Win Bytes", ft.get("Init_Win_bytes_forward"))
        recs.append(FlowRecord(src=f["src"], dst=f["dst"], sport=f.get("sport", 0), dport=f["dport"], proto=f["proto"],
                               start=f["start"], end=f["end"], packets=f["packets"], bytes=f["bytes"],
                               fwd_bytes=f.get("fwd_bytes", 0.0),
                               bwd_bytes=float(ft.get("Bwd Packets Length Total", 0) or 0),
                               init_fwd_win=int(win) if win not in (None, "") else None))
    return recs


def main() -> None:  # pragma: no cover - CLI
    run_dir = Path(sys.argv[1])
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    report = {"run": run_dir.name, "per_scenario": {}}
    for run in manifest["runs"]:
        recs = lab_flow_records(run_dir, run["scenario"])
        report["per_scenario"][run["scenario"]] = {
            "flows": len(recs),
            **{r.name: [asdict(x) for x in r.evaluate(recs)] for r in RULES},
        }
        print(run["scenario"], {r.name: len(report["per_scenario"][run["scenario"]][r.name]) for r in RULES}, flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("wrote", OUT)


if __name__ == "__main__":  # pragma: no cover
    main()
