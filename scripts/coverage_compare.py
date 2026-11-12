# -*- coding: utf-8 -*-
"""DEV vs HELD-OUT coverage, side by side (v5.3.0).

    python scripts/coverage_compare.py   # reads docs/purple_team/{dev,heldout}/results.json

DEV (runs 2+3) is what the v5.3.0 rules were tuned on; HELD-OUT (run4, fresh seed) was recorded
before tuning and analysed only after the rules were frozen (commit ae84496). Never averaged.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PT = REPO / "docs" / "purple_team"
OUT = PT / "dev_vs_heldout.md"


def _cell(r: dict) -> str:
    if r is None:
        return "—"
    layers = ", ".join(r["observed_layers"]) or "none"
    mttd = "not detected" if r["mttd_s"] is None else f"{r['mttd_s']:.1f} s"
    return f"**{r['outcome']}** · {layers} · {r.get('l3_attack_type') or 'L3: not detected'} · {mttd}"


def render(dev: dict, held: dict) -> str:
    d = {r["scenario"]: r for r in dev["results"]}
    h = {r["scenario"]: r for r in held["results"]}
    lines = ["| Scenario | Expected | DEV (runs 2+3: tuned on) | HELD-OUT (run4: never tuned on) |", "|---|---|---|---|"]
    for sid in sorted(set(d) | set(h)):
        ref = d.get(sid) or h.get(sid)
        exp = (f"{ref['expected_family']} via {'+'.join(ref['expected_layers'])}" if ref.get("expected_incident")
               else "no incident")
        lines.append(f"| `{sid}` | {exp} | {_cell(d.get(sid))} | {_cell(h.get(sid))} |")

    def tally(rs):
        from collections import Counter

        return dict(Counter(r["outcome"] for r in rs))

    lines += ["", f"DEV outcomes: {tally(dev['results'])}; HELD-OUT outcomes: {tally(held['results'])}.",
              f"Model fingerprint DEV `{dev.get('model_fingerprint')}`, HELD-OUT `{held.get('model_fingerprint')}`."]
    return "\n".join(lines)


def main() -> None:  # pragma: no cover - CLI
    dev = json.loads((PT / "dev" / "results.json").read_text(encoding="utf-8"))
    held = json.loads((PT / "heldout" / "results.json").read_text(encoding="utf-8"))
    md = render(dev, held)
    OUT.write_text("# Coverage: DEV vs HELD-OUT (v5.3.0)\n\n" + md + "\n", encoding="utf-8")
    print(md)


if __name__ == "__main__":
    sys.exit(main())
