# -*- coding: utf-8 -*-
"""v5.3.0 DEV vs held-out table: both columns, 'not detected' kept, never averaged."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("cc", Path(__file__).resolve().parent.parent / "scripts" / "coverage_compare.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)


def r(sid, outcome, layers, l3, mttd, inc=True):
    return {"scenario": sid, "outcome": outcome, "observed_layers": layers, "l3_attack_type": l3, "mttd_s": mttd,
            "expected_incident": inc, "expected_family": "syn_flood" if inc else None, "expected_layers": ["L1", "L3"] if inc else []}


def test_side_by_side():
    dev = {"model_fingerprint": "a", "results": [r("syn_flood", "detected", ["L1", "L3"], "TCP SYN flood", 0.1),
                                                 r("flash_crowd", "clean", [], None, None, inc=False)]}
    held = {"model_fingerprint": "a", "results": [r("syn_flood", "partial", ["L1"], None, 1.2),
                                                  r("flash_crowd", "false_positive", ["L1"], None, 3.0, inc=False)]}
    md = cc.render(dev, held)
    assert "| `syn_flood` | syn_flood via L1+L3 | **detected** · L1, L3 · TCP SYN flood · 0.1 s | **partial** · L1 · L3: not detected · 1.2 s |" in md
    assert "| `flash_crowd` | no incident | **clean** · none · L3: not detected · not detected |" in md
    assert "HELD-OUT outcomes: {'partial': 1, 'false_positive': 1}" in md
